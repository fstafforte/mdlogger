#!/bin/bash


MCAST_ROUT_SET=$(route -n | grep 224 | grep 240)

if [ "$MCAST_ROUT_SET" == "" ]; then
    echo -n "Enter the network interface name where enable multicast routing: "
    read
    NETWOR_ITF=$REPLY
    sudo route add -net 224.0.0.0 netmask 240.0.0.0 dev $NETWOR_ITF
    [ $? -ne 0 ] && exit -1
    route -n
fi 

cargo test --package mdlogger --lib -- tests::finalize_uninitialize_mdlogger --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::wrong_config_file_path --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::message_pattern --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::file_basename --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::wrong_timestamp_format --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::missing_root_handler --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::log_handler_chain_loop --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::console_missing_redirection --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::console_wrong_redirection --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::console_wrong_log_message_format --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::console_handler --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::rollingfile_wrong_basename --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::rollingfile_wrong_maxsize --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::rollingfile_wrong_sizeum --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::rollingfile_handler --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1


FILES=$(ls -r ../logs/*)

for FILE in $FILES
do
    echo -n "hit return to show file: "$FILE
    read
    cat $FILE
done


cargo test --package mdlogger --lib -- tests::network_wrong_protocol --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::network_wrong_remote_address --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::network_wrong_remote_port --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::network_wrong_proto_unicast_addr_mcast --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::network_wrong_proto_mcast_addr_unicast --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::network_wrong_multicast_if --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::network_wrong_ipaddress_multicast_if --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::network_wrong_addrmcasttipv4_itfipv6 --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

cargo test --package mdlogger --lib -- tests::network_wrong_addrmcasttipv6_itfipv4 --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

target/debug/mdlogger_test_helper -t udp -a 127.0.0.1 -p 8000 &

cargo test --package mdlogger --lib -- tests::network_udp_ipv4_unicast --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

pkill -15 -f mdlogger_test_helper


target/debug/mdlogger_test_helper -t udp -a ::1 -p 8000 &

cargo test --package mdlogger --lib -- tests::network_udp_ipv6_unicast --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

pkill -15 -f mdlogger_test_helper


target/debug/mdlogger_test_helper -t mcast -a 239.0.0.1 -p 8000 &

cargo test --package mdlogger --lib -- tests::network_udp_ipv4_multicast --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

pkill -15 -f mdlogger_test_helper


target/debug/mdlogger_test_helper -t mcast -a 239.0.0.1 -p 8000 -i 192.168.239.130 &

cargo test --package mdlogger --lib -- tests::network_udp_ipv4_multicast_specific_itf --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

pkill -15 -f mdlogger_test_helper



target/debug/mdlogger_test_helper -t mcast -a ff02::1:ff00:1 -p 8000 &

cargo test --package mdlogger --lib -- tests::network_udp_ipv6_multicast --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

pkill -15 -f mdlogger_test_helper


target/debug/mdlogger_test_helper -t mcast -a ff02::1:ff00:1 -i fe80::64d4:e4c9:a9f6:f7af -p 8000 &


cargo test --package mdlogger --lib -- tests::network_udp_ipv6_multicast_specific_itf --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

pkill -15 -f mdlogger_test_helper


target/debug/mdlogger_test_helper -t tcp -a 127.0.0.1 -p 8000 &

cargo test --package mdlogger --lib -- tests::network_tcp_ipv4 --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

pkill -15 -f mdlogger_test_helper


target/debug/mdlogger_test_helper -t tcp -a ::1 -p 8000 &

cargo test --package mdlogger --lib -- tests::network_tcp_ipv6 --exact --nocapture --include-ignored
[ $? -ne 0 ] && exit -1

pkill -15 -f mdlogger_test_helper

sudo route del -net 224.0.0.0 netmask 240.0.0.0 dev $NETWOR_ITF

exit 0

