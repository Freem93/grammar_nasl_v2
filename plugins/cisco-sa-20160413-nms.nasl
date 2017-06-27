#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90766);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2016-1378");
  script_osvdb_id(137050);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum62591");
  script_xref(name:"IAVB", value:"2016-B-0075");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160413-nms");

  script_name(english:"Cisco Catalyst Switches NMSP Port Information Disclosure Vulnerability (cisco-sa-20160413-nms)");
  script_summary(english:"Attempts to grab the banner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Catalyst switch is affected by an information
disclosure vulnerability in IOS due to a failure by the Network
Mobility Services Protocol (NMSP) daemon to require authentication.
A remote attacker can exploit this, via a request to the NMSP port,
to gain version information about the software release running on the
device, which can be used to facilitate further attacks.");
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160413-nms
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?a2687cb1");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20160413-nms.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# see if port is open
port = 16113; # NMSP
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "TCP");

# try to open TCP socket
soc = open_sock_tcp(port);
if(!soc) audit(AUDIT_SOCK_FAIL, port, "TCP");

# attempt banner grab
banner = recv_line(socket:soc, length:4096);
close(soc);
if (empty_or_null(banner)) audit(AUDIT_RESP_NOT, port, "banner grab", "TCP");

flag = FALSE;
extra = "";
if ("IOS" >< banner && "Cisco" >< banner && "Version" >< banner)
{
  flag = TRUE;
  idx = stridx(banner, "Cisco IOS");
  if (idx > -1)
  {
    # Find text that starts with "Cisco IOS"
    sub = substr(banner, idx);
    extra = '\nThe following banner was obtained: \n\n' + sub;
  }
  else
    extra = '\nHowever, the information could not be' +
            '\nextracted successfully for reporting.';
}

if (flag)
{
  report = '\nNessus was able to grab a banner containing' +
           '\nversion information about the software release' +
           '\nrunning on the Cisco device by accessing the Network' +
           '\nMobility Services Protocol (NMSP) port.\n' +
           extra;

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_HOST_NOT, "affected");
