import os
from libnmap.objects.report import NmapReport
from libnmap.parser import NmapParser, NmapParserException

from .script_parsers import get_parser, get_output_name


def parse(out_dir, scan_id, logger):
    result = {"raw_data": {}, "is_up": None, "port_count": None, "ports": {}}
    for ext in "nmap", "gnmap", "xml":
        path = os.path.join(out_dir, f"nmap.{scan_id}.{ext}")
        try:
            with open(path, "r") as f:
                result["raw_data"][f"{ext}_data"] = f.read()
        except IOError:
            logger.warning(f"Couldn't read {path}")
            return False

    try:
        nmap_report = NmapParser.parse(result["raw_data"]["xml_data"])
    except NmapParserException:
        logger.warning(f"Couldn't parse nmap.{scan_id}.xml")
        return False

    if nmap_report.hosts_total != 1:
        logger.warning(
            f"Unexpected number of hosts found in nmap.{scan_id}.xml ({nmap_report.hosts_total})"
        )
        return False
    elif nmap_report.hosts_down == 1:
        # host is down
        result["is_up"] = False
    elif nmap_report.hosts_up == 1 and len(nmap_report.hosts) == 0:
        # host is up but no reportable ports were found
        result["is_up"] = True
        result["port_count"] = 0
    else:
        # host is up and reportable ports were found
        result["is_up"] = nmap_report.hosts[0].is_up()
        result["port_count"] = len(nmap_report.hosts[0].get_ports())
        result["ports"] = parse_ports(nmap_report)
    return result


def parse_ports(nmap_report: NmapReport):
    ports = []
    for port in nmap_report.hosts[0].get_open_ports():
        srv = nmap_report.hosts[0].get_service(port[0], port[1])
        portinfo = srv.get_dict()
        portinfo["service"] = srv.service_dict
        portinfo["scripts"] = []
        for script in srv.scripts_results:
            scriptsave = {"id": script["id"], "output": script["output"]}
            portinfo["scripts"].append(scriptsave)
            if get_parser(script["id"]):
                portinfo[get_output_name(script["id"])] = get_parser(script["id"])(
                    script
                )

        ports.append(portinfo)
    return ports
