import { LeaderboardType } from '../../../../enums/leaderboard-type.enum';

export interface MapSubmissionSuggestionsModel {
  [track: number]: {
    [mode in Gamemode]: {
      tier: number;
      gameplayQuality: number;
      leaderboardType: LeaderboardType;
    };
  };
}
