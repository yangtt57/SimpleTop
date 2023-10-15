gcc mytop.c -lcurses -o mytop
source /etc/profile
echo $cursorrow
cursorrow=1
while :
do 
./mytop
sleep 3
done