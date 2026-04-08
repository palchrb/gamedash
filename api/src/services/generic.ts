/**
 * Generic service adapter — lifecycle + logs only.
 *
 * For games like Among Us, Factorio (without RCON), Mindustry, Valheim,
 * etc. The adapter exposes start/stop/restart/status/logs and nothing
 * else. Users can knock to reach the configured ports and admins can
 * manage the container from the dashboard; no game-specific features.
 */

import { BaseAdapter } from "./base";
import type { ServiceConfig } from "../schemas";

export class GenericAdapter extends BaseAdapter {
  constructor(config: ServiceConfig) {
    super(config);
    this.capabilities.add("logs");
  }
}
