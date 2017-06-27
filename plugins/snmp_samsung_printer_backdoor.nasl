#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63136);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/21 20:34:34 $");

  script_cve_id("CVE-2012-4964");
  script_bugtraq_id(56692);
  script_osvdb_id(87872);
  script_xref(name:"CERT", value:"281284");

  script_name(english:"Samsung / Dell Printer SNMP Backdoor");
  script_summary(english:"Tries to get model information.");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer has a backdoor administrator account.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Samsung printer, or a Dell printer
manufactured by Samsung. It has a hard-coded SNMP read-write community
string that allows access even when SNMP has been disabled in the
printer management utility. A remote, unauthenticated attacker can
exploit this to take control of the printer.");
  # https://web.archive.org/web/20121201035625/http://l8security.com/post/36715280176/vu-281284-samsung-printer-snmp-backdoor
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?693ace24");
  # https://web.archive.org/web/20121211110451/http://www.samsung.com/us/article/samsung-security-advisory-on-snmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef2777ed");
  script_set_attribute(attribute:"solution", value:"
To secure the printer, do one or more of the following :

  - Limit access to the affected SNMP service using a secure
    firewall / router. 

  - Disable SNMPv1/v2 on the printer and instead use the
    secure SNMPv3 mode.

  - Apply an optional firmware update. Contact the device's
    vendor for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:samsung:printer_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SNMP");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("dont_print_on_printers.nasl", "dont_scan_printers.nasl", "dont_scan_printers2.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = 161;
if (!get_udp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, 'UDP');

secret_public = 's!a@m#n$p%c';
oids = make_array(
  '1.3.6.1.4.1.236.11.5.1.1.1.1.0', 'Model name',
  '1.3.6.1.4.1.236.11.5.1.1.1.2.0', 'Software version',
  '1.3.6.1.4.1.236.11.5.1.1.1.3.0', 'Model version'
);
results = '';

# skip over snmp agents that reply to everything
soc = open_sock_udp(port);
if (!soc)
  audit(AUDIT_SOCK_FAIL, port, 'UDP');

res = snmp_request(socket:soc, community:secret_public, oid:'1.3.6.1.2.1.43.8.2.1.14.1.1'); # prtInputVendorName
close(soc);

if (tolower(res) !~ '(samsung|dell)')
  audit(AUDIT_HOST_NOT, 'Samsung/Dell printer');

# if we're pretty sure it's a samsung or dell, verify that it's a
# vulnerable box by trying to get more information out of it
foreach oid (keys(oids))
{
  soc = open_sock_udp(port);
  if (!soc)
  {
    # only bail out if we haven't gotten any results yet
    if (strlen(results) == 0)
      audit(AUDIT_SOCK_FAIL, port, 'UDP');
    else
      break;  # if partial results were obtained, report on them
  }

  res = snmp_request(socket:soc, community:secret_public, oid:oid);
  close(soc);

  if (!isnull(res) && res !~ '^ *$')
    results += '\n  ' + oids[oid] + ' : ' + res;
}
  
if (strlen(results) == 0)
  audit(AUDIT_RESP_NOT, port, 'SNMP request', 'UDP', code:0);

if (report_verbosity > 0)
{
  report =
    '\nNessus used the hard-coded backdoor SNMP community string "' + secret_public + '"' +
    '\nto access the following information :' +
    '\n' +
    results + '\n';
  security_hole(port:port, extra:report, protocol:"udp");
}
else security_hole(port:port, protocol:"udp");
