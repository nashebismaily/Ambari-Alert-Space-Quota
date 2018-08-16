# ambari-alert-space-quota
Custom Ambari alert for HDFS spaceQuota in a kerberized and Namenode HA HDP cluster 

## Installing custom Ambari alert
curl -u admin:admin -i -H 'X-Requested-By:ambari' -X POST -d @alerts.json  http://node1.example.com:8080/api/v1/clusters/ClusterDemo/alert_definitions
