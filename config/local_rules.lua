-- Local Snort 3 Rules
-- Add your custom rules here

ips =
{
    rules =
    [[
        -- Test rules for basic functionality
        alert icmp any any -> any any (msg:"ICMP Test Rule"; sid:1000001;)
        alert tcp any any -> any 80 (msg:"HTTP Test Rule"; sid:1000002;)
        alert tcp any any -> any 443 (msg:"HTTPS Test Rule"; sid:1000003;)
        
        -- Example detection rules
        alert tcp any any -> any 22 (msg:"SSH Connection"; sid:1000004;)
        alert tcp any any -> any 21 (msg:"FTP Connection"; sid:1000005;)
        alert tcp any any -> any 23 (msg:"Telnet Connection"; sid:1000006;)
    ]]
}
