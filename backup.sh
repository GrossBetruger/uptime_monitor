year=$(date +%Y)
month=$(date +%m)
day=$(date +%d)
hour=$(date +%H)
minute=$(date +%M)

stamp="$year-$month-$day-$hour:$minute"
curl http://34.68.19.97:3000/logs > "backups/backup-$stamp.txt"


