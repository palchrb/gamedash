/**
 * Generic adapter — for any container that just needs lifecycle + logs.
 *
 * Use this for games like Among Us / Impostor, Factorio (without RCON),
 * Mindustry, Valheim, etc. The adapter exposes start/stop/restart/status/logs
 * and nothing else. The user gets knock-based access on the configured ports
 * and can manage the container from the admin dashboard, but no game-specific
 * features (whitelist, RCON commands, world management) are available.
 */

const BaseAdapter = require("./base");

class GenericAdapter extends BaseAdapter {
  constructor(config) {
    super(config);
    this.capabilities = new Set(["lifecycle", "logs"]);
  }
}

module.exports = GenericAdapter;
