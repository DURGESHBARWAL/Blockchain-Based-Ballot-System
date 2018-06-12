import supersqlite as ssql, json, address

DB_MANAGER = ssql.SSQLiteManager('public_details.db')

TOTAL_VOTERS = DB_MANAGER.len('ELIGIBLE_VOTERS')

t = DB_MANAGER.select('OFFICER_DETAILS')

BLO_PUBLIC_KEY, BLO_ID = json.loads(t[0][0]), address.getId(t[0][1], t[0][2])[1]
EXT_OFFICER_PUBLIC_KEY, EXT_OFFICER_ID = json.loads(t[1][0]), address.getId(t[1][1], t[1][2])[1]

DB_MANAGER.close()
