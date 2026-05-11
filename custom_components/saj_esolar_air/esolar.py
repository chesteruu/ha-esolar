"""ESolar Cloud Platform data fetchers."""
import calendar
import datetime
from datetime import timedelta
import hashlib
import logging
import random
import string
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests

_LOGGER = logging.getLogger(__name__)

WEB_TIMEOUT = 10

BASIC_TEST = False
VERBOSE_DEBUG = False
if BASIC_TEST:
    from .esolar_static_test import (
        get_esolar_data_static_h1_r5,
        web_get_plant_static_h1_r5,
    )


EOP_BASE_URL = "https://eop.saj-electric.com"
AES_KEY_HEX = "ec1840a7c53cf0709eb784be480379b6"
AES_KEY = bytes.fromhex(AES_KEY_HEX)
SECRET_KEY = "ktoKRLgQPjvNyUZO8lVc9kU1Bsip6XIe"
CLIENT_ID = "esolar-monitor-admin"
APP_PROJECT = "elekeeper"


@dataclass
class ESolarSession:
    """Session wrapper for SAJ eop API."""

    session: requests.Session
    token: str | None = None


def _encrypt_password(password: str) -> str:
    """Encrypt password with SAJ's AES-128-ECB + PKCS7 scheme."""
    block_size = 16
    padding_len = block_size - (len(password) % block_size)
    padded_password = password.encode("utf-8") + bytes([padding_len] * padding_len)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_password) + encryptor.finalize()
    return encrypted.hex()


def _generate_random_string(length: int = 32) -> str:
    """Generate random alpha-numeric string."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def _generate_signature(params: dict) -> str:
    """Generate SAJ API signature."""
    sorted_keys = sorted(params.keys())
    param_str = "&".join(f"{k}={params[k]}" for k in sorted_keys)
    param_str += f"&key={SECRET_KEY}"
    md5_hash = hashlib.md5(param_str.encode("utf-8")).hexdigest()
    return hashlib.sha1(md5_hash.encode("utf-8")).hexdigest().upper()


def _build_request_params(extra_params: dict | None = None) -> dict:
    """Build common request parameters with SAJ API signature."""
    params = {
        "appProjectName": APP_PROJECT,
        "clientDate": datetime.datetime.now().strftime("%Y-%m-%d"),
        "lang": "en",
        "timeStamp": str(int(datetime.datetime.now().timestamp() * 1000)),
        "random": _generate_random_string(32),
        "clientId": CLIENT_ID,
    }
    if extra_params:
        params.update(extra_params)

    signature = _generate_signature(params)
    params["signParams"] = ",".join(sorted(params.keys()))
    params["signature"] = signature
    return params


def _api_post(
    session: ESolarSession,
    endpoint: str,
    payload: dict,
    *,
    with_auth: bool = True,
) -> requests.Response:
    """POST to new SAJ eop API with signed request parameters."""
    headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "lang": "en",
    }
    if with_auth and session.token:
        headers["Authorization"] = f"Bearer {session.token}"

    response = session.session.post(
        f"{EOP_BASE_URL}{endpoint}",
        data=_build_request_params(payload),
        headers=headers,
        timeout=WEB_TIMEOUT,
    )
    response.raise_for_status()
    return response


def _api_get(
    session: ESolarSession,
    endpoint: str,
    query: dict,
    *,
    with_auth: bool = True,
) -> requests.Response:
    """GET from new SAJ eop API with signed request parameters."""
    headers = {
        "lang": "en",
        "accept": "application/json",
    }
    if with_auth and session.token:
        headers["Authorization"] = f"Bearer {session.token}"

    response = session.session.get(
        f"{EOP_BASE_URL}{endpoint}",
        params=_build_request_params(query),
        headers=headers,
        timeout=WEB_TIMEOUT,
    )
    response.raise_for_status()
    return response


def _api_extract_json(response: requests.Response) -> dict:
    """Normalize SAJ API response shape and return payload."""
    data = response.json()
    code = data.get("code")
    if code is None:
        code = data.get("errCode")
    if code not in (0, 200):
        msg = data.get("msg") or data.get("errMsg") or f"Unexpected code {code}"
        raise ValueError(msg)
    return data.get("data", {})


def add_months(sourcedate, months):
    """SAJ eSolar Helper Function - Adds a months to input."""
    month = sourcedate.month - 1 + months
    year = sourcedate.year + month // 12
    month = month % 12 + 1
    day = min(sourcedate.day, calendar.monthrange(year, month)[1])
    return datetime.date(year, month, day)


def add_years(source_date, years):
    """SAJ eSolar Helper Function - Adds a years to input."""
    try:
        return source_date.replace(year=source_date.year + years)
    except ValueError:
        return source_date + (
            datetime.date(source_date.year + years, 1, 1)
            - datetime.date(source_date.year, 1, 1)
        )


def _to_float(value, default=0.0):
    """Safely convert value to float."""
    try:
        if value is None or value == "":
            return float(default)
        return float(value)
    except (TypeError, ValueError):
        return default


def web_get_one_device_info(session: ESolarSession, device_sn: str) -> dict:
    """Retrieve one device payload from SAJ eop API."""
    response = _api_get(
        session,
        "/dev-api/api/v1/monitor/device/getOneDeviceInfo",
        {"deviceSn": device_sn},
    )
    return _api_extract_json(response)


def _build_plant_info_from_device(device_sn: str, device_data: dict) -> dict:
    """Adapt one-device API payload into existing plantList model."""
    stats = device_data.get("deviceStatisticsData", {})

    pv_power = _to_float(stats.get("powerNow"))
    load_data = stats.get("loadData", {}) if isinstance(stats.get("loadData"), dict) else {}
    load_power = _to_float(
        stats.get("totalLoadPowerwatt"),
        _to_float(load_data.get("systotalloadwatt"), 0.0),
    )
    home_load_power = _to_float(
        stats.get("homeLoadPowerwatt"),
        _to_float(stats.get("homeLoadPower"), load_power),
    )
    backup_load_power = _to_float(stats.get("backUptotalLoadPowerwatt"), 0.0)
    grid_power = _to_float(stats.get("sysGridPowerwatt"))
    bat_power = _to_float(stats.get("batPower"))
    bat_soc = _to_float(stats.get("batCapcity"))
    today_pv_energy = _to_float(stats.get("todayPvEnergy"))
    total_pv_energy = _to_float(stats.get("totalPvEnergy"))

    is_online = int(stats.get("isOnline", 0) or 0) == 1
    running_state = 1 if is_online else 3
    has_battery = bat_soc > 0 or abs(bat_power) > 0
    plant_type = 3 if has_battery else 0

    plant_uid = str(device_data.get("plantuid") or device_data.get("plantUid") or device_sn)
    plant_name = str(device_data.get("plantName") or f"Device {device_sn}")
    inverter_model = str(device_data.get("deviceModel") or "SAJ Inverter")
    address = str(device_data.get("plantAddress") or "")
    country = str(device_data.get("countryCode") or "")

    grid_direction = 0
    if grid_power < 0:
        grid_direction = 1
    elif grid_power > 0:
        grid_direction = -1

    battery_direction = 0
    if bat_power > 0:
        battery_direction = -1
    elif bat_power < 0:
        battery_direction = 1

    # Keep existing sensor model by synthesizing expected keys.
    plant = {
        "plantuid": plant_uid,
        "plantname": plant_name,
        "systempower": max(pv_power, 0.0),
        "currency": "EUR",
        "type": plant_type,
        "country": country,
        "address": address,
        "runningState": running_state,
        "nowPower": pv_power,
        "todayElectricity": today_pv_energy,
        "totalElectricity": total_pv_energy,
        "plantDetail": {
            "type": plant_type,
            "runningState": running_state,
            "nowPower": pv_power,
            "todayElectricity": today_pv_energy,
            "totalElectricity": total_pv_energy,
            "income": None,
            "totalReduceCo2": _to_float(device_data.get("totalReduceCo2")),
            "totalPlantTreeNum": _to_float(device_data.get("totalPlantTreeNum")),
            "totalBuyElec": None,
            "totalSellElec": total_pv_energy,
            "snList": [device_sn],
        },
        "peakList": [{"devicesn": device_sn, "peakPower": _to_float(stats.get("peakPower"), pv_power)}],
        "beanList": [
            {
                "pvElec": today_pv_energy,
                "useElec": _to_float(stats.get("todayLoadEnergy")),
                "buyElec": _to_float(stats.get("todayBuyEnergy")),
                "sellElec": _to_float(stats.get("todaySellEnergy")),
                "chargeElec": _to_float(stats.get("todayBatChgEnergy")),
                "dischargeElec": _to_float(stats.get("todayBatDisEnergy")),
                "buyRate": str(stats.get("buyRate") or "0"),
                "sellRate": str(stats.get("sellRate") or "0"),
                "devicesn": device_sn,
            }
        ],
        "kitList": [
            {
                "devicetype": inverter_model,
                "type": 2 if has_battery else 0,
                "devicesn": device_sn,
                "devicepc": str(device_data.get("devicepc") or ""),
                "displayfw": str(device_data.get("displayfw") or ""),
                "mastermcufw": str(device_data.get("mastermcufw") or ""),
                "kitSn": str(device_data.get("kitSn") or device_sn),
                "todaySellEnergy": today_pv_energy,
                "monthSellEnergy": _to_float(stats.get("monthPvEnergy")),
                "totalSellEnergy": total_pv_energy,
                "onLineStr": "1" if is_online else "3",
                "powernow": pv_power,
                "findRawdataPageList": {
                    "pV1Volt": _to_float(stats.get("pV1Volt")),
                    "pV2Volt": _to_float(stats.get("pV2Volt")),
                    "pV3Volt": _to_float(stats.get("pV3Volt")),
                    "pV1Curr": _to_float(stats.get("pV1Curr")),
                    "pV2Curr": _to_float(stats.get("pV2Curr")),
                    "pV3Curr": _to_float(stats.get("pV3Curr")),
                    "rGridVolt": _to_float(stats.get("rGridVolt")),
                    "sGridVolt": _to_float(stats.get("sGridVolt")),
                    "tGridVolt": _to_float(stats.get("tGridVolt")),
                    "rGridCurr": _to_float(stats.get("rGridCurr")),
                    "sGridCurr": _to_float(stats.get("sGridCurr")),
                    "tGridCurr": _to_float(stats.get("tGridCurr")),
                    "rGridFreq": _to_float(stats.get("rGridFreq")),
                    "sGridFreq": _to_float(stats.get("sGridFreq")),
                    "tGridFreq": _to_float(stats.get("tGridFreq")),
                    "deviceType": 0,
                },
                "storeDevicePower": {
                    "batCapcity": 100.0,
                    "batCapcityStr": "100Ah",
                    "batCurr": _to_float(stats.get("batCurr")),
                    "batEnergyPercent": bat_soc,
                    "batteryPower": bat_power,
                    "batteryDirection": battery_direction,
                    "gridPower": grid_power,
                    "gridDirection": grid_direction,
                    "inputOutputPower": _to_float(stats.get("inputOutputPower")),
                    "outPutDirection": int(stats.get("outPutDirection") or 0),
                    "pvPower": pv_power,
                    "pvDirection": int(stats.get("pvDirection") or 0),
                    "totalLoadPower": load_power,
                    "homeLoadPower": home_load_power,
                    "backupLoadPower": _to_float(stats.get("backupLoadPower"), backup_load_power),
                    "solarPower": pv_power,
                },
            }
        ],
        # Keep full raw payloads so HA can expose complete runtime telemetry.
        "_raw_device_data": device_data,
        "_raw_device_statistics": stats,
        "status": "success",
    }

    return {"status": "success", "plantList": [plant]}


def get_esolar_data(
    region,
    username,
    password,
    plant_list=None,
    use_pv_grid_attributes=True,
    device_sn=None,
):
    """SAJ eSolar Data Update."""
    if BASIC_TEST:
        return get_esolar_data_static_h1_r5(
            region, username, password, plant_list, use_pv_grid_attributes
        )

    if not device_sn:
        raise ValueError("Missing device SN")

    try:
        session = esolar_web_autenticate(region, username, password)
        device_data = web_get_one_device_info(session, device_sn)
        plant_info = _build_plant_info_from_device(device_sn, device_data)
        if plant_list is not None:
            selected = [
                plant
                for plant in plant_info["plantList"]
                if plant["plantname"] in plant_list
            ]
            plant_info = {"status": "success", "plantList": selected}

    except requests.exceptions.HTTPError as errh:
        raise requests.exceptions.HTTPError(errh)
    except requests.exceptions.ConnectionError as errc:
        raise requests.exceptions.ConnectionError(errc)
    except requests.exceptions.Timeout as errt:
        raise requests.exceptions.Timeout(errt)
    except requests.exceptions.RequestException as errr:
        raise requests.exceptions.RequestException(errr)
    except ValueError as errv:
        raise ValueError(errv) from errv

    return plant_info


def esolar_web_autenticate(region, username, password):
    """Authenticate the user to the SAJ's WEB Portal."""
    if BASIC_TEST:
        return True

    try:
        eop_session = ESolarSession(session=requests.Session())
        response = _api_post(
            eop_session,
            "/dev-api/api/v1/sys/login",
            {
                "username": username,
                "password": _encrypt_password(password),
                "loginType": "1",
            },
            with_auth=False,
        )
        login_data = _api_extract_json(response)
        token = login_data.get("token")
        if token:
            eop_session.token = token
            _LOGGER.debug("Authenticated with SAJ eop API")
            return eop_session
        raise ValueError("Missing token in SAJ eop login response")

    except requests.exceptions.HTTPError as errh:
        raise requests.exceptions.HTTPError(errh)
    except requests.exceptions.ConnectionError as errc:
        raise requests.exceptions.ConnectionError(errc)
    except requests.exceptions.Timeout as errt:
        raise requests.exceptions.Timeout(errt)
    except requests.exceptions.RequestException as errr:
        raise requests.exceptions.RequestException(errr)


def web_get_plant(region, session, requested_plant_list=None):
    """Retrieve the platUid from WEB Portal using web_authenticate."""
    if session is None:
        raise ValueError("Missing session identifier trying to obain plants")

    if BASIC_TEST:
        return web_get_plant_static_h1_r5()

    try:
        output_plant_list = []
        response = _api_post(
            session,
            "/dev-api/api/v1/monitor/site/getUserPlantList",
            {
            "pageNo": "",
            "pageSize": "",
            "orderByIndex": "",
            "officeId": "",
            "clientDate": datetime.date.today().strftime("%Y-%m-%d"),
            "runningState": "",
            "selectInputType": "",
            "plantName": "",
            "deviceSn": "",
            "type": "",
            "countryCode": "",
            "isRename": "",
            "isTimeError": "",
            "systemPowerLeast": "",
            "systemPowerMost": "",
            },
        )
        plant_list = _api_extract_json(response)
        if "plantList" not in plant_list and "list" in plant_list:
            plant_list = {"plantList": plant_list["list"]}
        if "status" not in plant_list:
            plant_list["status"] = "success"
        if requested_plant_list is not None:
            for plant in plant_list["plantList"]:
                if plant["plantname"] in requested_plant_list:
                    output_plant_list.append(plant)
            return {"status": plant_list["status"], "plantList": output_plant_list}

        return plant_list

    except requests.exceptions.HTTPError as errh:
        raise requests.exceptions.HTTPError(errh)
    except requests.exceptions.ConnectionError as errc:
        raise requests.exceptions.ConnectionError(errc)
    except requests.exceptions.Timeout as errt:
        raise requests.exceptions.Timeout(errt)
    except requests.exceptions.RequestException as errr:
        raise requests.exceptions.RequestException(errr)


def web_get_plant_details(region, session, plant_info):
    """Retrieve platUid from the WEB Portal using web_authenticate."""
    if session is None:
        raise ValueError("Missing session identifier trying to obain plants")

    try:
        device_list = []
        for plant in plant_info["plantList"]:
            response = _api_post(
                session,
                "/dev-api/api/v1/monitor/site/getPlantDetailInfo",
                {
                    "plantuid": plant["plantuid"],
                    "clientDate": datetime.date.today().strftime("%Y-%m-%d"),
                },
            )
            plant_detail = _api_extract_json(response)
            plant.update(plant_detail)
            for device in plant_detail["plantDetail"]["snList"]:
                device_list.append(device)

    except requests.exceptions.HTTPError as errh:
        raise requests.exceptions.HTTPError(errh)
    except requests.exceptions.ConnectionError as errc:
        raise requests.exceptions.ConnectionError(errc)
    except requests.exceptions.Timeout as errt:
        raise requests.exceptions.Timeout(errt)
    except requests.exceptions.RequestException as errr:
        raise requests.exceptions.RequestException(errr)


def web_get_plant_detailed_chart(region, session, plant_info):
    """Retrieve the kitList from the WEB Portal with web_authenticate."""
    if session is None:
        raise ValueError("Missing session identifier trying to obain plants")

    try:
        today = datetime.date.today()
        previous_chart_day = today - timedelta(days=1)
        next_chart_day = today + timedelta(days=1)
        chart_day = today.strftime("%Y-%m-%d")
        previous_chart_month = add_months(today, -1).strftime("%Y-%m")
        next_chart_month = add_months(today, 1).strftime("%Y-%m")
        chart_month = today.strftime("%Y-%m")
        previous_chart_year = add_years(today, -1).strftime("%Y")
        next_chart_year = add_years(today, 1).strftime("%Y")
        chart_year = today.strftime("%Y")
        client_date = datetime.date.today().strftime("%Y-%m-%d")

        for plant in plant_info["plantList"]:
            #
            # NOTE : This URL now takes a sinle inverter, but it should somehow take a list
            #
            # deviceSnArr={plant['plantDetail']['snList'][0]  <<== Is correct if there is only one inverter in the system
            #
            bean = []
            peak_pow = []
            for inverter in plant["plantDetail"]["snList"]:
                query = {
                    "plantuid": plant["plantuid"],
                    "chartDateType": 1,
                    "energyType": 0,
                    "clientDate": client_date,
                    "deviceSnArr": "" if plant["type"] == 3 else inverter,
                    "chartCountType": 2,
                    "previousChartDay": str(previous_chart_day),
                    "nextChartDay": str(next_chart_day),
                    "chartDay": chart_day,
                    "previousChartMonth": previous_chart_month,
                    "nextChartMonth": next_chart_month,
                    "chartMonth": chart_month,
                    "previousChartYear": previous_chart_year,
                    "nextChartYear": next_chart_year,
                    "chartYear": chart_year,
                    "elecDevicesn": inverter if plant["type"] == 3 else "",
                }
                response = _api_get(
                    session, "/dev-api/api/v1/monitor/site/getPlantDetailChart2", query
                )
                plant_chart = _api_extract_json(response)
                if VERBOSE_DEBUG:
                    _LOGGER.debug(
                        "\n.../getPlantDetailChart2\n------------------------\n%s",
                        plant_chart,
                    )
                if (plant_chart["type"]) == 0:
                    tmp = {}
                    tmp.update({"devicesn": inverter})
                    tmp.update({"peakPower": plant_chart["peakPower"]})
                    peak_pow.append(tmp)
                    plant.update({"peakList": peak_pow})
                    # plant.update({"peakPower": plant_chart["peakPower"]})
                elif (plant_chart["type"]) == 1:
                    plant_chart["viewBean"].update({"devicesn": inverter})
                    bean.append(plant_chart["viewBean"])
                    plant.update({"beanList": bean})

    except requests.exceptions.HTTPError as errh:
        raise requests.exceptions.HTTPError(errh)
    except requests.exceptions.ConnectionError as errc:
        raise requests.exceptions.ConnectionError(errc)
    except requests.exceptions.Timeout as errt:
        raise requests.exceptions.Timeout(errt)
    except requests.exceptions.RequestException as errr:
        raise requests.exceptions.RequestException(errr)


def web_get_device_page_list(region, session, plant_info, use_pv_grid_attributes):
    """Retrieve the platUid from the WEB Portal with web_authenticate."""
    if session is None:
        raise ValueError("Missing session identifier trying to obain plants")

    try:
        for plant in plant_info["plantList"]:
            _LOGGER.debug("Plant UID: %s", plant["plantuid"])
            _LOGGER.debug("Plant Type: %s", plant["type"])

            chart_month = datetime.date.today().strftime("%Y-%m")
            response = _api_post(
                session,
                "/dev-api/api/v1/cloudMonitor/device/findDevicePageList",
                {
                    "officeId": "1",
                    "pageNo": "",
                    "pageSize": "",
                    "orderName": "1",
                    "orderType": "2",
                    "plantuid": plant["plantuid"],
                    "deviceStatus": "",
                    "localDate": datetime.date.today().strftime("%Y-%m-%d"),
                    "localMonth": chart_month,
                },
            )
            device_list = _api_extract_json(response).get("list", [])
            if VERBOSE_DEBUG:
                _LOGGER.debug(
                    "\n.../findDevicePageList\n----------------------\n%s", device_list
                )

            kit = []
            for device in device_list:
                if device["devicesn"] not in plant["plantDetail"]["snList"]:
                    continue
                _LOGGER.debug("Device SN: %s", device["devicesn"])
                if use_pv_grid_attributes:
                    response = _api_post(
                        session,
                        "/dev-api/api/v1/cloudMonitor/deviceInfo/findRawdataPageList",
                        {
                            "deviceSn": device["devicesn"],
                            "deviceType": device["type"],
                            "timeStr": datetime.date.today().strftime("%Y-%m-%d"),
                        },
                    )
                    find_rawdata_page_list = _api_extract_json(response)
                    _LOGGER.debug(
                        "Result length   : %s", len(find_rawdata_page_list["list"])
                    )

                    if len(find_rawdata_page_list["list"]) > 0:
                        device.update(
                            {"findRawdataPageList": find_rawdata_page_list["list"][0]}
                        )
                    else:
                        device.update({"findRawdataPageList": None})

                    if VERBOSE_DEBUG and len(find_rawdata_page_list["list"]) > 0:
                        _LOGGER.debug(
                            "\n.../findRawdataPageList\n-----------------------\n%s",
                            find_rawdata_page_list["list"][0],
                        )

                # Fetch battery for H1 system (UNTESTED CODE)
                if plant["type"] == 3:
                    _LOGGER.debug("Fetching storage information")
                    response = _api_post(
                        session,
                        "/dev-api/api/v1/monitor/site/getStoreOrAcDevicePowerInfo",
                        {
                            "plantuid": plant["plantuid"],
                            "devicesn": device["devicesn"],
                        },
                    )
                    store_device_power = _api_extract_json(response)
                    device.update(store_device_power)
                    if VERBOSE_DEBUG:
                        _LOGGER.debug(
                            "getStoreOrAcDevicePowerInfo\n-------------------------------\n%s",
                            store_device_power,
                        )

                kit.append(device)

            plant.update({"kitList": kit})

    except requests.exceptions.HTTPError as errh:
        raise requests.exceptions.HTTPError(errh)
    except requests.exceptions.ConnectionError as errc:
        raise requests.exceptions.ConnectionError(errc)
    except requests.exceptions.Timeout as errt:
        raise requests.exceptions.Timeout(errt)
    except requests.exceptions.RequestException as errr:
        raise requests.exceptions.RequestException(errr)
