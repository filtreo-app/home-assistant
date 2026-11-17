"""Configurazione dalla schermata di Home Assistant.

Con l'add-on Filtreo (stesso apparecchio di Home Assistant) l'add-on lascia in collegamento.json la porta e la chiave:
basta un clic. Con Filtreo su un altro apparecchio (per esempio il Jetson) si scrivono indirizzo, porta e chiave
(il pannello di Filtreo, Impostazioni → «Home Assistant e HomeKit», li mostra).
"""
from __future__ import annotations

import json
import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import FiltreoChiaveErrata, FiltreoErrore, prova
from .const import CONF_TOKEN, DOMAIN, FILE_COLLEGAMENTO, HOST_CANDIDATI, PORTA_PREDEFINITA

_LOGGER = logging.getLogger(__name__)


def _leggi_collegamento(hass: HomeAssistant) -> dict[str, Any]:
    try:
        with open(hass.config.path(FILE_COLLEGAMENTO), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) and d.get("token") else {}
    except (OSError, ValueError):
        return {}


class FiltreoConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._auto: dict[str, Any] = {}

    async def _controlla(self, host: str, porta: int, token: str) -> tuple[dict[str, Any] | None, str | None]:
        try:
            dati = await prova(async_get_clientsession(self.hass), host, porta, token)
        except FiltreoChiaveErrata:
            return None, "invalid_auth"
        except FiltreoErrore:
            return None, "cannot_connect"
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Errore inatteso parlando con Filtreo")
            return None, "unknown"
        return dati, None

    async def _crea(self, host: str, porta: int, token: str, dati: dict[str, Any]) -> ConfigFlowResult:
        await self.async_set_unique_id(dati.get("nodo") or f"{host}:{porta}")
        self._abort_if_unique_id_configured(updates={CONF_HOST: host, CONF_PORT: porta, CONF_TOKEN: token})
        return self.async_create_entry(title="Filtreo", data={CONF_HOST: host, CONF_PORT: porta, CONF_TOKEN: token})

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is None:
            # add-on sullo stesso apparecchio: provo gli indirizzi noti con la chiave lasciata dall'add-on
            coll = await self.hass.async_add_executor_job(_leggi_collegamento, self.hass)
            if coll:
                porta = int(coll.get("porta") or PORTA_PREDEFINITA)
                for host in HOST_CANDIDATI:
                    dati, err = await self._controlla(host, porta, coll["token"])
                    if dati is not None:
                        self._auto = {CONF_HOST: host, CONF_PORT: porta, CONF_TOKEN: coll["token"], "dati": dati}
                        return await self.async_step_conferma()
        errori: dict[str, str] = {}
        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            porta = int(user_input[CONF_PORT])
            dati, err = await self._controlla(host, porta, user_input[CONF_TOKEN].strip())
            if dati is not None:
                return await self._crea(host, porta, user_input[CONF_TOKEN].strip(), dati)
            errori["base"] = err or "unknown"
        schema = vol.Schema({
            vol.Required(CONF_HOST, default=(user_input or {}).get(CONF_HOST, "")): str,
            vol.Required(CONF_PORT, default=(user_input or {}).get(CONF_PORT, PORTA_PREDEFINITA)): int,
            vol.Required(CONF_TOKEN): str,
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errori)

    async def async_step_conferma(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        a = self._auto
        if user_input is not None:
            return await self._crea(a[CONF_HOST], a[CONF_PORT], a[CONF_TOKEN], a["dati"])
        return self.async_show_form(step_id="conferma", description_placeholders={"host": a[CONF_HOST]})

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        voce = self._get_reauth_entry()
        errori: dict[str, str] = {}
        if user_input is not None:
            dati, err = await self._controlla(voce.data[CONF_HOST], voce.data[CONF_PORT], user_input[CONF_TOKEN].strip())
            if dati is not None:
                return self.async_update_reload_and_abort(voce, data_updates={CONF_TOKEN: user_input[CONF_TOKEN].strip()})
            errori["base"] = err or "unknown"
        return self.async_show_form(step_id="reauth_confirm", data_schema=vol.Schema({vol.Required(CONF_TOKEN): str}),
                                    errors=errori)
