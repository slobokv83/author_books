import redis
from server.utils.utils import REDIS_PORT


jwt_redis_blocklist = redis.Redis(
    host="localhost", port=REDIS_PORT, db=0, decode_responses=True)
