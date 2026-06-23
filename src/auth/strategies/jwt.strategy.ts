import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { CACHE_MANAGER } from "@nestjs/cache-manager";
import type { Cache } from "cache-manager";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { User } from "../../users/user.entity";

interface JwtPayload {
  sub: number;
  role?: string;
  isBlocked?: boolean;
  wardId?: number;
  tokenVersion?: number;
}

/**
 * Build the Redis/in-memory cache key that holds the *current* tokenVersion
 * for a given user. The cache is written when a user is blocked / unblocked /
 * deleted (or any other "revoke all sessions" event), and read by this
 * strategy on every authenticated request.
 *
 * Exported so other services can write to the same key.
 */
export const tokenVersionCacheKey = (userId: number) =>
  `user:${userId}:tokenVersion`;

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject(CACHE_MANAGER) private readonly cache: Cache,
    @InjectRepository(User) private readonly userRepo: Repository<User>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  // Returns the user identity straight from the JWT — avoids a DB lookup on
  // every authenticated request. Revocation is enforced via a Redis-backed
  // tokenVersion: when a user is blocked or otherwise has their sessions
  // revoked, the new tokenVersion is written to the cache; this strategy
  // rejects any JWT whose tokenVersion is older than the cached value.
  //
  // On cache miss (Redis down / TTL expired), falls back to a DB lookup to
  // ensure revoked sessions are still rejected (fail-closed).
  async validate(payload: JwtPayload) {
    if (payload.isBlocked) {
      throw new UnauthorizedException("User is blocked");
    }

    const presented = payload.tokenVersion ?? 0;
    const cached = await this.cache.get<number>(
      tokenVersionCacheKey(payload.sub),
    );

    if (cached !== undefined && cached !== null) {
      if (presented < Number(cached)) {
        throw new UnauthorizedException("Session has been revoked");
      }
    } else {
      // Cache miss — fall back to DB to ensure fail-closed behaviour.
      const user = await this.userRepo.findOne({
        where: { id: payload.sub },
        select: ["tokenVersion"],
      });
      if (user && presented < user.tokenVersion) {
        throw new UnauthorizedException("Session has been revoked");
      }
    }

    return {
      id: payload.sub,
      role: payload.role,
      wardId: payload.wardId,
      tokenVersion: presented,
    };
  }
}
