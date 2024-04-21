#!/bin/bash
# -*- coding: utf-8 -*-
set -eo pipefail
PATH=/usr/local/bin:$PATH

function usage() {
    cat << EOF
Usage: $(basename $0) -d|-a|-c|-x|-e|-g|-q -i <target.tld|targets.txt> -p <port spec> -t <threads> -r <rate> -n <enable notifications> -s <enable screenshotting> -j <enable nmap scan> -o <results_dir> -n <notifications> -v -h
-d      domain mode
-a      ASN mode
-c      CIDR mode
-x      certificate transparency mode (crt.sh)
-e      naabu portscan mode
-g      masscan portscan mode
-z      vuln scan mode (nuclei)
-q      js-scrape mode (katana + nuclei)
-i      mandatory: input, can be a domain/subdomain e.g., example.com/test.example.com, an ASN e.g., AS12345 or a CIDR 10.11.12.13/20
        or a file
-p      mandatory: port spec, choices from: top100, top1000, small, medium, large, xlarge
-k      mandatory: nuclei templates for -z
-f      optional: scope type for js-scrape mode, dn|rdn|fqdn or regex
-t      optional: threads to use for all tools, default 16
-r      optional: max pps for port scanning, default 512
-n      optional: enable notifications, use slack-webhook|slack|discord|telegram|teams; configuration file /etc/notify/notify-config-portscan.yaml for portscan, /etc/notify/notify-config-subdomains.yaml for subdomains etc
-s      optional: enable web screenshotting with gowitness
-j      optional: enable nmap scanning on port scan results
-o      optional: output directory
-v      optional: verbose, enable execution tracing in bash
-l      list the ports spec
-y      list nuclei templates
-h      display help message
-H      display extended help message

Examples:
subdomain, portscan, screenshots            $(basename $0) -d -i example.com -p large -s
asn, portscan, notifications                $(basename $0) -a -i AS1234 -p top100 -n slack
cidr, portscan, nmap, notifications         $(basename $0) -c -i 10.11.12.13/20 -p small -j -n slack-webhook
ct, portscan, nmap, notifications           $(basename $0) -x -i example.com -p small -j -n slack-webhook
naabu portscan, nmap, screenshots           $(basename $0) -e -i example.com -p small -j -s
masscan portscan, nmap, screenshots         $(basename $0) -g -i example.com -p small -j -s
vulnscan, notifications                     $(basename $0) -z -i example.com
EOF
}

function extended_usage() {
    cat << EOF
Automated active recon script starting starting from a base domain/subdomain, ASN or CIDR.
Will expand the base target(s) and perform a port scan specified by -p and visual reconnaissance.

Can be used in a crontab, e.g., daily + notifications on new results after first usage

Zips results after each run in the output dir e.g.,
    if output dir is /root/recon/target.tld, zip is /root/recon/target.tld_<mode>.zip

Requires the following ProjectDiscovery toolset: subfinder, asnmap, mapcidr, masscan, naabu, gowitness, notify
Request the custom ct-monitor crt.sh tool

General pipeline and workflow:
    base target(s) - domain(s)/ASN(s)/CIDR(s)
      |
      +-> subdomains/ASN IP blocks/CIDR to IP blocks
            |
            +-> portscan
                  |
                  +-> gowitness visual inspection

Usage: $(basename $0) -d|-a|-c|-x|-e|-g -i <target.tld|targets.txt> -p <port spec> -t <threads> -r <rate> -n <enable notifications> -s <enable screenshotting> -j <enable nmap scan> -o <results_dir> -n <notifications> -v -h
-d      domain mode
-a      ASN mode
-c      CIDR mode
-x      certificate transparency mode (crt.sh)
-e      naabu portscan mode
-g      masscan portscan mode
-z      vuln scan mode (nuclei)
-q      js-scrape mode (katana + nuclei)
-i      mandatory: input, can be a domain/subdomain e.g., example.com/test.example.com, an ASN e.g., AS12345 or a CIDR 10.11.12.13/20
        or a file
-p      mandatory: port spec, choices from: top100, top1000, small, medium, large, xlarge
-k      mandatory: nuclei templates for -z
-t      optional: threads to use for all tools, default 16
-r      optional: max pps for port scanning, default 512
-n      optional: enable notifications, use slack-webhook|slack|discord|telegram|teams; configuration file /etc/notify/notify-config-portscan.yaml for portscan, /etc/notify/notify-config-subdomains.yaml for subdomains etc
-s      optional: enable web screenshotting with gowitness
-j      optional: enable nmap scanning on port scan results
-o      optional: output directory
-v      optional: verbose, enable execution tracing in bash
-l      list the ports spec
-y      list nuclei templates
-h      display this help message
-H      display extended help message

Examples:
subdomain, portscan, screenshots            $(basename $0) -d -i example.com -p large -s
asn, portscan, notifications                $(basename $0) -a -i AS1234 -p top100 -n slack
cidr, portscan, nmap, notifications         $(basename $0) -c -i 10.11.12.13/20 -p small -j -n slack-webhook
ct, portscan, nmap, notifications           $(basename $0) -x -i example.com -p small -j -n slack-webhook
naabu portscan, nmap, screenshots           $(basename $0) -e -i example.com -p small -j -s
masscan portscan, nmap, screenshots         $(basename $0) -g -i example.com -p small -j -s
vulnscan, notifications                     $(basename $0) -z -i example.com

Crontab example:
PATH=/usr/local/bin:/usr/local/go/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
SHELL=/bin/bash

0 15 * * * /usr/local/bin/oneshot.sh -d -i target.tld -p large -o /root/recon/target.tld &>/dev/null
EOF
    exit 1
}

function ports_usage() {
    cat << EOF
top100  - nmap top100
top1000 - nmap top1000
small   - 80,443
medium  - 80,443,8000,8080,8443
large   - 80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888
xlarge  - 80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017
full    - 1-65535
EOF
    exit 1
}

function list_templates() {
    mkdir -p "${HOME}/nuclei-templates" &>/dev/null
    command nuclei -update-templates -update-template-dir "${HOME}/nuclei-templates" -silent

    if [[ $(command -v tree) ]]; then
        tree -f -a "${HOME}/nuclei-templates" | less
    else 
        ls -R "${HOME}/nuclei-templates" | less
    fi
}

function precheck() {
    if [[ -n $notifications ]]; then
        if [[ ! -f /etc/notify/notify-config-subdomains.yaml ]]; then
            printf "%s\n" "/etc/notify/notify-config-subfinder.yaml not found, skipping subdomains notifications"
            notifications=""
        fi

        if [[ ! -f /etc/notify/notify-config-ct.yaml ]]; then
            printf "%s\n" "/etc/notify/notify-config-ct.yaml not found, skipping certificate transparency notifications"
            notifications=""
        fi
        
        if [[ ! -f /etc/notify/notify-config-portscan.yaml ]]; then
            printf "%s\n" "/etc/notify/notify-config.yaml not found, skipping portscan notifications"
            notifications=""
        fi
    fi

    if [[ ! -f /etc/subfinder/subfinder-config.yaml ]]; then
        printf "%s\n" "/etc/subfinder/subfinder-config.yaml not found, using default (empty) config"
        subfinder_config="${HOME}/.config/subfinder/provider-config.yaml"
    else
        subfinder_config="/etc/subfinder/subfinder-config.yaml"
    fi

    if [[ $screenshot == true ]]; then
        if [[ ! $(command -v google-chrome) ]]; then
            printf "%s\n" "[-] enabled screenshotting, but google-chrome not found; disabling"
            screenshot=false
        fi

        if [[ ! $(command -v google-chrome-stable) ]]; then
            printf "%s\n" "[-] enabled screenshotting, but google-chrome not found; disabling"
            screenshot=false
        fi
    fi
}

[[ $# -eq 0 ]] && usage

user_agents=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Safari/605.1.15"
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
)
random_user_agent="${user_agents[$(( RANDOM % ${#user_agents[@]} ))]}"

templates=()
while getopts "dacxegzqi:p:k:f:t:r:n:sjo:vlyhH" ARG; do
    case "${ARG}" in
        d) action="domain";;
        a) action="asn";;
        c) action="cidr";;
        x) action="certificate_transparency";;
        e) action="naabu_portscan";;
        g) action="masscan_portscan";;
        z) action="vulnscan";;
        q) action="jsscrape";;
        i) input="${OPTARG}";;
        p)
            case "${OPTARG}" in
                top100)
                    ports="top100"
                    ports_arg="-p 7,9,13,21,22,23,25,26,37,53,79,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157"
                    ;;
                top1000)
                    ports="top1000"
                    ports_arg="-p 1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"
                    ;;
                small)
                    ports="web-small"
                    ports_arg="-p 80,443"
                    ;;
                medium)
                    ports="web-medium"
                    ports_arg="-p 80,443,8000,8080,8443"
                    ;;
                large)
                    ports="web-large"
                    ports_arg="-p 80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888"
                    ;;
                xlarge)
                    ports="web-xlarge"
                    ports_arg="-p 80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017"
                    ;;
                full)
                    ports="full"
                    ports_arg="-p -"
                    ;;
            esac
            ;;
        k) templates+=("${OPTARG}");;
        f) scope="${OPTARG}";;
        t) threads="${OPTARG}";;
        r) rate="${OPTARG}";;
        n) case "${OPTARG}" in
               slack-webhook)
                   notifications="slack-webhook";;
               slack)
                   notifications="slack";;
               discord)
                   notifications="discord";;
               telegram)
                   notifications="telegram";;
               teams)
                   notifications="teams";;
               *)
                   notifications="";;
           esac
           ;;
        s) screenshot=true;;
        j) nmap_scan=true;;
        o) output_dir="${OPTARG}";;
        v) set -x;;
        l) ports_usage;;
        y) list_templates;;
        h) usage;;
        H) extended_usage;;
        *) usage;;
    esac
done

template_arg=""
for i in "${templates[@]}"; do
    template_arg+="-t ${i} "
done

[[ -z "${action}" ]] && printf "%s\n" "must use one of the scan modes" && exit 1
if [[ -n "${action}" && -z "${input}" ]]; then
    printf "%s\n" "must supply -i as target input for ${action} mode"
    exit 1
fi

if [[ "${action}" == "vulnscan" ]]; then
    if [[ -z "${template_arg}" ]]; then
        printf "%s\n" \
            "must supply templates with -k for ${action} mode on ${input}"
        exit 1
    fi
else
    if [[ ! "${action}" == "jsscrape" ]]; then
        if [[ -z "${ports}" ]]; then
            printf "%s\n" \
                "must supply -p as port spec for ${action} mode on ${input}" \
                "use -l to list port scan options"
            exit 1
        fi
    fi
fi

deps=(
    ct-monitor
    notify
    subfinder
    asnmap
    mapcidr
    naabu
    gowitness
    anew
    zip
    nmap
    httpx
    nuclei
    katana
    google-chrome
    google-chrome-stable
)
for dep in "${deps[@]}"; do
    if [[ ! $(command -v $dep) ]]; then
        printf "%s\n" "$dep not found or not in path, exiting"
        exit 1
    fi
done

[[ -z "${scope}" ]] && scope="rdn"
threads="${threads:-16}"
rate="${rate:-512}"
timestamp="$(date -u --rfc-3339=seconds | sed 's/+00:00//' | tr ' ' '_' | tr '+:' '-')"
target_name="$(printf "%s" "${input}" | tr ':/ ' '-')"
DEFAULT_DIR="./${target_name}_${action}_recon_${ports}"
RECON_DIR="${output_dir:-$DEFAULT_DIR}"
mkdir -p "${RECON_DIR}/logs" &>/dev/null
mkdir -p "${RECON_DIR}" &>/dev/null
[[ "${action}" != masscan_portscan ]] && exec > >(tee "${RECON_DIR}/logs/recon-${timestamp}.log") 2>&1

if [[ -f $input ]]; then
    subfinder_input_arg="-dL $input"
    asnmap_input_arg="-f $input"
    mapcidr_input_arg="-cl $input"
    ct_input_arg="-f $input"
    naabu_input_arg="-list $input"
    nuclei_input_arg="-list $input"
    if [[ $action == masscan_portscan ]]; then
        > "${RECON_DIR}/${input}_dns-resolved.csv"
        for i in $(cat $input); do
            if ! [[ $i =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                for resolved in $(dig +short $i); do
                    printf "%s\n" "${i},${resolved}" >> "${RECON_DIR}/${input}_dns-resolved.csv"
                done
            else
                printf "%s\n" "nxdomain,${i}" >> "${RECON_DIR}/${input}_dns-resolved.csv"
            fi
        done
        masscan_input_arg="${RECON_DIR}/${input}_dns-resolved.csv"
    fi
    cp $input "${RECON_DIR}/targets.txt"
elif [[ ! -f $input ]]; then
    subfinder_input_arg="-d $input"
    asnmap_input_arg="-asn $input"
    mapcidr_input_arg="-cidr $input"
    ct_input_arg="-d $input"
    naabu_input_arg="-host $input"
    nuclei_input_arg="-target $input"
    if [[ $action == masscan_portscan ]]; then
        > "${RECON_DIR}/${input}_dns-resolved.csv"
        if ! [[ $i =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            resolved=$(dig +short $input)
            printf "%s\n" "${input},${resolved}" >> "${RECON_DIR}/${input}_dns-resolved.csv"
        else
            printf "%s\n" "nxdomain,${input}" >> "${RECON_DIR}/${input}_dns-resolved.csv"
        fi
        masscan_input_arg="${RECON_DIR}/${input}_dns-resolved.csv"
    fi
    printf "%s\n" "${input}" > "${RECON_DIR}/targets.txt"
fi

precheck

case "${action}" in
    domain)
        command subfinder \
            $subfinder_input_arg \
            -t $threads \
            -provider-config "${subfinder_config}" \
            -all \
            -active \
            -no-color \
        | anew "${RECON_DIR}/subdomains_subfinder.txt" | { [[ -n $notifications ]] && notify -nc -duc -cl 2000 -bulk -pc /etc/notify/notify-config-subdomains.yaml -id $notifications || cat; } \
        | command naabu \
            $ports_arg \
            -c $threads \
            -rate $rate \
            -scan-all-ips \
            -ip-version 4 \
            -scan-type c \
            -skip-host-discovery \
            -no-color | anew "${RECON_DIR}/naabu_portscan_${ports}.txt" | { [[ -n $notifications ]] && notify -nc -duc -cl 2000 -bulk -pc /etc/notify/notify-config-portscan.yaml -id $notifications || cat; } \
        | { [[ $screenshot == true ]] && command gowitness \
            file -f - \
            --threads $threads \
            --disable-db \
            --fullpage \
            --user-agent "${random_user_agent}" \
            --screenshot-path "${RECON_DIR}/visual_recon" || cat; }
 
        if [[ $nmap_scan == true ]]; then
            declare -A targets_ports
            mkdir -p "${RECON_DIR}/nmap"

            while IFS=: read -r domain port; do
                if [[ -z ${targets_ports[$domain]} ]]; then
                    targets_ports["$domain"]=$port
                else
                    targets_ports["$domain"]+=",$port"
                fi
            done < "${RECON_DIR}/naabu_portscan_${ports}.txt"
            for domain in "${!targets_ports[@]}"; do
                nmap -sV -sT -T4 -Pn -n \
                    --resolve-all \
                    --min-rate $rate \
                    --min-hostgroup 4 \
                    --max-hostgroup 4 \
                    --open \
                    -p "${targets_ports[$domain]}" \
                    "${domain}" \
                    -oN "${RECON_DIR}/nmap/${domain}__${ports}__${timestamp}.nmap" \
                    -oG "${RECON_DIR}/nmap/${domain}__${ports}__${timestamp}.gnmap"
            done
        fi
        ;;
    asn)
        command asnmap \
            $asnmap_input_arg | anew "${RECON_DIR}/asn-recon.txt" \
        | command mapcidr \
            -filter-ipv4 \
            -skip-base \
            -skip-broadcast \
            -shuffle-ip | anew "${RECON_DIR}/asn_ips.txt" \
        | command naabu \
            $ports_arg \
            -c $threads \
            -rate $rate \
            -scan-all-ips \
            -ip-version 4 \
            -scan-type c \
            -skip-host-discovery \
            -no-color | anew "${RECON_DIR}/naabu_portscan_${ports}.txt" | { [[ -n $notifications ]] && notify -nc -duc -cl 2000 -bulk -pc /etc/notify/notify-config-portscan.yaml -id $notifications || cat; } \
        | { [[ $screenshot == true ]] && command gowitness \
            file -f - \
            --threads $threads \
            --disable-db \
            --fullpage \
            --user-agent "${random_user_agent}" \
            --screenshot-path "${RECON_DIR}/visual_recon" || cat; }

        if [[ $nmap_scan == true ]]; then
            declare -A targets_ports
            mkdir -p "${RECON_DIR}/nmap"

            while IFS=: read -r domain port; do
                if [[ -z ${targets_ports[$domain]} ]]; then
                    targets_ports["$domain"]=$port
                else
                    targets_ports["$domain"]+=",$port"
                fi
            done < "${RECON_DIR}/naabu_portscan_${ports}.txt"
            for domain in "${!targets_ports[@]}"; do
                nmap -sV -sT -T4 -Pn -n \
                    --resolve-all \
                    --min-rate $rate \
                    --min-hostgroup 4 \
                    --max-hostgroup 4 \
                    --open \
                    -p "${targets_ports[$domain]}" \
                    "${domain}" \
                    -oN "${RECON_DIR}/nmap/${domain}__${ports}__${timestamp}.nmap" \
                    -oG "${RECON_DIR}/nmap/${domain}__${ports}__${timestamp}.gnmap"
            done
        fi
        ;;
    cidr)
        command mapcidr \
            $mapcidr_input_arg \
            -filter-ipv4 \
            -skip-base \
            -skip-broadcast \
            -shuffle-ip | anew "${RECON_DIR}/cidr_ips.txt" \
        | command naabu \
            $ports_arg \
            -c $threads \
            -rate $rate \
            -scan-all-ips \
            -ip-version 4 \
            -scan-type c \
            -skip-host-discovery \
            -no-color | anew "${RECON_DIR}/naabu_portscan_${ports}.txt" | { [[ -n $notifications ]] && notify -nc -duc -cl 2000 -bulk -pc /etc/notify/notify-config-portscan.yaml -id $notifications || cat; } \
        | { [[ $screenshot == true ]] && command gowitness \
            file -f - \
            --threads $threads \
            --disable-db \
            --fullpage \
            --user-agent "${random_user_agent}" \
            --screenshot-path "${RECON_DIR}/visual_recon" || cat; }

        if [[ $nmap_scan == true ]]; then
            declare -A targets_ports
            mkdir -p "${RECON_DIR}/nmap"

            while IFS=: read -r domain port; do
                if [[ -z ${targets_ports[$domain]} ]]; then
                    targets_ports["$domain"]=$port
                else
                    targets_ports["$domain"]+=",$port"
                fi
            done < "${RECON_DIR}/naabu_portscan_${ports}.txt"
            for domain in "${!targets_ports[@]}"; do
                nmap -sV -sT -T4 -Pn -n \
                    --resolve-all \
                    --min-rate $rate \
                    --min-hostgroup 4 \
                    --max-hostgroup 4 \
                    --open \
                    -p "${targets_ports[$domain]}" \
                    "${domain}" \
                    -oN "${RECON_DIR}/nmap/${domain}__${ports}__${timestamp}.nmap" \
                    -oG "${RECON_DIR}/nmap/${domain}__${ports}__${timestamp}.gnmap"
            done
        fi
        ;;
    certificate_transparency)
        command ct-monitor \
            $ct_input_arg \
        | anew "${RECON_DIR}/${input}" | { [[ -n $notifications ]] && notify -nc -duc -cl 2000 -bulk -pc /etc/notify/notify-config-ct.yaml -id $notifications || cat; } \
        | command naabu \
            $ports_arg \
            -c $threads \
            -rate $rate \
            -scan-all-ips \
            -ip-version 4 \
            -scan-type c \
            -skip-host-discovery \
            -no-color | anew "${RECON_DIR}/naabu_portscan_${ports}.txt" | { [[ -n $notifications ]] && notify -nc -duc -cl 2000 -bulk -pc /etc/notify/notify-config-portscan.yaml -id $notifications || cat; } \
        | { [[ $screenshot == true ]] && command gowitness \
            file -f - \
            --threads $threads \
            --disable-db \
            --fullpage \
            --user-agent "${random_user_agent}" \
            --screenshot-path "${RECON_DIR}/visual_recon" || cat; }

        if [[ $nmap_scan == true ]]; then
            declare -A targets_ports
            mkdir -p "${RECON_DIR}/nmap"

            while IFS=: read -r domain port; do
                if [[ -z ${targets_ports[$domain]} ]]; then
                    targets_ports["$domain"]=$port
                else
                    targets_ports["$domain"]+=",$port"
                fi
            done < "${RECON_DIR}/naabu_portscan_${ports}.txt"
            for domain in "${!targets_ports[@]}"; do
                nmap -sV -sT -T4 -Pn -n \
                    --resolve-all \
                    --min-rate $rate \
                    --min-hostgroup 4 \
                    --max-hostgroup 4 \
                    --open \
                    -p "${targets_ports[$domain]}" \
                    "${domain}" \
                    -oN "${RECON_DIR}/nmap/${domain}__${ports}__${timestamp}.nmap" \
                    -oG "${RECON_DIR}/nmap/${domain}__${ports}__${timestamp}.gnmap"
            done
        fi
        ;;
    naabu_portscan)
        command naabu \
            -duc \
            $naabu_input_arg \
            $ports_arg \
            -c $threads \
            -rate $rate \
            -scan-all-ips \
            -ip-version 4 \
            -scan-type c \
            -skip-host-discovery \
            -no-color | tee "${RECON_DIR}/naabu_portscan_${ports}.txt" \
        | { [[ $screenshot == true ]] && command gowitness \
            file -f - \
            --threads $threads \
            --disable-db \
            --fullpage \
            --user-agent "${random_user_agent}" \
            --screenshot-path "${RECON_DIR}/visual_recon" || cat; }

        if [[ $nmap_scan == true ]]; then
            declare -A targets_ports
            mkdir -p "${RECON_DIR}/nmap"

            while IFS=: read -r domain port; do
                if [[ -z ${targets_ports[$domain]} ]]; then
                    targets_ports["$domain"]=$port
                else
                    targets_ports["$domain"]+=",$port"
                fi
            done < "${RECON_DIR}/naabu_portscan_${ports}.txt"
            for domain in "${!targets_ports[@]}"; do
                nmap -sV -sT -T4 -Pn -n \
                    --resolve-all \
                    --min-rate $rate \
                    --min-hostgroup 4 \
                    --max-hostgroup 4 \
                    --open \
                    -p "${targets_ports[$domain]}" \
                    "${domain}" \
                    -oN "${RECON_DIR}/nmap/${domain}__${ports}__${timestamp}.nmap" \
                    -oG "${RECON_DIR}/nmap/${domain}__${ports}__${timestamp}.gnmap"
            done
        fi
        ;;
    masscan_portscan)
        mkdir -p "${RECON_DIR}/masscan" &>/dev/null
        lowpriv_user=$(logname)
        [[ $EUID -ne 0 ]] && printf "%s\n" "masscan mode requires root" && exit 1
        for i in $(cat $masscan_input_arg); do
            resolved_ip=$(echo $i | cut -d ',' -f2)
            original_target=$(echo $i | cut -d ',' -f1)
            masscan $resolved_ip \
                $ports_arg \
                --rate $rate \
                --wait 10 \
                --open-only | tee -a "${RECON_DIR}/masscan_portscan_${ports}.txt" | awk '{print $6":"$4}' | sed 's/\/tcp//g' | tee "${RECON_DIR}/masscan/${original_target}_${resolved_ip}_portscan_${ports}.txt" \
            | { [[ $screenshot == true ]] && command gowitness \
                file -f - \
                --threads $threads \
                --disable-db \
                --fullpage \
                --user-agent "${random_user_agent}" \
                --screenshot-path "${RECON_DIR}/visual_recon" || cat; }
        done

        if [[ $nmap_scan == true ]]; then
            declare -A targets_ports
            for i in ${RECON_DIR}/masscan/*; do
                domain=$(echo $(basename $i) | cut -d '_' -f1)
                ip=$(echo $(basename $i) | cut -d '_' -f2)

                mkdir -p "${RECON_DIR}/nmap" &>/dev/null

                while IFS=: read -r target port; do
                    if [[ -z ${targets_ports[$target]} ]]; then
                        targets_ports["${domain}_${ip}"]=$port
                    else
                        targets_ports["${domain}_${ip}"]+=",$port"
                    fi
                done < $i
            done
            for target in "${!targets_ports[@]}"; do
                domain=$(echo $target | cut -d '_' -f1)
                ip=$(echo $target | cut -d '_' -f2)
                nmap -sV -sT -T4 -Pn -n \
                    --resolve-all \
                    --min-rate $rate \
                    --min-hostgroup 4 \
                    --max-hostgroup 4 \
                    --open \
                    -p "${targets_ports[$target]}" \
                    "${ip}" \
                    -oN "${RECON_DIR}/nmap/${domain}_${ip}__${ports}__${timestamp}.nmap" \
                    -oG "${RECON_DIR}/nmap/${domain}_${ip}__${ports}__${timestamp}.gnmap"
            done
        fi
        chown -R "${lowpriv_user}:${lowpriv_user}" "${RECON_DIR}"
        ;;
    vulnscan)
        command nuclei \
            -duc \
            -stats \
            -no-color \
            $template_arg \
            -sa \
            -c $threads \
            -headless \
            $nuclei_input_arg | anew "${RECON_DIR}/nuclei.txt" | { [[ -n $notifications ]] && notify -nc -duc -cl 2000 -bulk -pc /etc/notify/notify-config-nuclei.yaml -id $notifications || cat; }
        ;;
    jsscrape)
        {
            echo $input
            katana -sc -duc -no-color -fs $scope -c $threads -p $threads -u $input -em js
        } | nuclei -duc -no-color -c $threads -headc $threads -t jsscrape.yaml | tee "${RECON_DIR}/jsscrape_${target_name}.txt"
        ;;
esac

zip_name="${target_name}_${action}_recon_${ports}__${timestamp}.zip"
(cd "${RECON_DIR}"; rm -rf "${zip_name}"; zip -q -r "../${zip_name}" .)
[[ $action == masscan_portscan ]] && chown -R "${lowpriv_user}:${lowpriv_user}" "${zip_name}"
printf "%s\n" "[*] Zipped results in \"${RECON_DIR}/${zip_name}\""
