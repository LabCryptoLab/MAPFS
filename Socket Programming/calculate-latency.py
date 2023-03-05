#tcp-latency 169.254.69.248 --port 8080 --runs 20 


from tcp_latency import measure_latency

measure_latency(host='169.254.69.248', port=8080, runs=10, timeout=2.5)
