% Load Prolog files
:- ['rule.p'].

digital_entity("google_chrome_browser").
digital_entity("cloudflare_cdn").
digital_entity("HAproxy_load_balancer").
digital_entity("auth0_authentication_service").
digital_entity("nginx_api_gateway").
digital_entity("express_backend").
digital_entity("mySQL_database").
digital_entity("minIO_storage_service").
digital_entity("aws_backup").
digital_entity("prometheus_monitoring_service").
digital_entity("http_connection").
digital_entity("sql_request_response").

vulnerability("CVE-2025-47275").
vulnerability("CVE-2025-1974").
vulnerability("CVE-2025-23419").
vulnerability("CVE-2024-43796").
vulnerability("CVE-2025-53023").
vulnerability("CVE-2023-45539").

threat("unauthorizedAccess").
threat("remoteCodeExecution").
threat("informationLeakage").
threat("xss").
threat("denialOfService").
threat("misrouting").

misbehavior("misconfiguration").
misbehavior("unavailability").
misbehavior("dataCorruption").
misbehavior("overload").

exposed("nginx_api_gateway","CVE-2025-1974").
exposed("express_backend","CVE-2024-43796").
exposed("mySQL_database","CVE-2025-53023").
exposed("HAproxy_load_balancer","CVE-2023-45539").

exploitable("CVE-2025-47275","unauthorizedAccess").
exploitable("CVE-2025-1974","remoteCodeExecution").
exploitable("CVE-2025-23419","informationLeakage").
exploitable("CVE-2024-43796","xss").
exploitable("CVE-2025-53023","denialOfService").
exploitable("CVE-2023-45539","misrouting").
exploitable("CVE-2023-45539","informationLeakage").

cause("denialOfService","unavailability").
cause("misrouting","overload").

induce("misconfiguration","CVE-2025-47275").
induce("misconfiguration","CVE-2025-23419").
induce("overload","CVE-2025-53023").

connect("http_connection","google_chrome_browser","cloudflare_cdn").
connect("http_connection","cloudflare_cdn","google_chrome_browser").
connect("http_connection","cloudflare_cdn","nginx_api_gateway").
connect("http_connection","nginx_api_gateway","cloudflare_cdn").
connect("http_connection","nginx_api_gateway","HAproxy_load_balancer").
connect("http_connection","HAproxy_load_balancer","nginx_api_gateway").
connect("http_connection","HAproxy_load_balancer","express_backend").
connect("http_connection","express_backend","HAproxy_load_balancer").
connect("http_connection","express_backend","auth0_authentication_service").
connect("http_connection","auth0_authentication_service","express_backend").
connect("sql_request_response","express_backend","mySQL_database").
connect("sql_request_response","mySQL_database","express_backend").
connect("sql_request_response","mySQL_database","aws_backup").
connect("sql_request_response","aws_backup","mySQL_database").
connect("http_connection","express_backend","minIO_storage_service").
connect("http_connection","minIO_storage_service","express_backend").
connect("http_connection","express_backend","prometheus_monitoring_service").
connect("http_connection","prometheus_monitoring_service","express_backend").

control("express_backend","mySQL_database").
control("express_backend","minIO_storage_service").

monitor("prometheus_monitoring_service","express_backend","unauthorizedAccess").
monitor("prometheus_monitoring_service","express_backend","denialOfService").

spread("express_backend","unauthorizedAccess","CVE-2024-43796").
spread("mySQL_database","denialOfService","CVE-2025-53023").
spread("nginx_api_gateway","remoteCodeExecution","CVE-2025-1974").
spread("express_backend","xss","CVE-2024-43796").
spread("mySQL_database","denialOfService","CVE-2025-53023").
spread("HAproxy_load_balancer","misrouting","CVE-2023-45539").
spread("HAproxy_load_balancer","informationLeakage","CVE-2023-45539").
spread("auth0_authentication_service","unauthorizedAccess","CVE-2025-47275").
spread("auth0_authentication_service","informationLeakage","CVE-2025-23419").

assMalfun("auth0_authentication_service","misconfiguration").
