year=$(date +%Y)
month=$(date +%m)
day=$(date +%d)
hour=$(date +%H)
minute=$(date +%M)

stamp="$year-$month-$day-$hour:$minute"
curl http://34.55.225.231:3000/logs > "backups/backup-$stamp.txt"


