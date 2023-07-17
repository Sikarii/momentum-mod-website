import { Gamemode } from '../enums/map-type.enum';

/**
 * The MapTypes that will accept run submissions
 */
export const AllowedMapTypes: ReadonlyArray<Gamemode> = Object.freeze([
  Gamemode.SURF,
  Gamemode.BHOP,
  Gamemode.RJ,
  Gamemode.SJ,
  Gamemode.AHOP,
  Gamemode.CONC,
  Gamemode.DEFRAG
]);
