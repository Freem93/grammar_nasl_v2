#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2012/10/09. Deprecated by smb_nt_ms12-067.nasl.

include("compat.inc");

if (description)
{
  script_id(60155);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/06/09 19:35:27 $");

  script_cve_id(
    "CVE-2012-1766",
    "CVE-2012-1767",
    "CVE-2012-1768",
    "CVE-2012-1769",
    "CVE-2012-1770",
    "CVE-2012-1771",
    "CVE-2012-1772",
    "CVE-2012-1773",
    "CVE-2012-3106",
    "CVE-2012-3107",
    "CVE-2012-3108",
    "CVE-2012-3109",
    "CVE-2012-3110"
  );
  script_bugtraq_id(
    54497,
    54500,
    54504,
    54506,
    54511,
    54531,
    54536,
    54541,
    54543,
    54546,
    54548,
    54550,
    54554
  );
  script_osvdb_id(
    83900,
    83901,
    83902,
    83903,
    83904,
    83905,
    83906,
    83907,
    83908,
    83909,
    83910,
    83911,
    83913,
    83944
  );
  script_xref(name:"CERT", value:"118913");
  script_xref(name:"Secunia", value:"49936");

  script_name(english:"Microsoft Security Advisory 2737111: Vulnerabilities in FAST Search Server 2010 for SharePoint Parsing Could Allow Remote Code Execution (deprecated)");
  script_summary(english:"Checks if workarounds are being used");

  script_set_attribute(
    attribute:"synopsis",
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This plugin originally checked for the workaround described in
Microsoft Security Advisory 2737111, and has been deprecated due to
the publication of MS12-067.  Microsoft has released a patch that
makes the workaround unnecessary.  To check for the patch, use Nessus
plugin ID xxxxx."
  );
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("fast_search_server_installed.nasl");
  script_require_keys("SMB/fast_search_server/path", "SMB/fast_search_server/prodtype");
  script_require_ports(139, 445);

  exit(0);
}
exit(0, "This plugin has been deprecated. Use smb_nt_ms12-067.nasl (plugin ID 62462) instead.");

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

global_var login, pass, domain;

##
# checks whether or not the given configuration file is using the
# workaround described by kb2737111
#
# @anonparam path path of the XML configuration file to check
# @return the line of the config file that indicates the workaround isn't being used,
#         NULL otherwise
##
function _is_fast_vulnerable()
{
  local_var path, vuln_line, rc, fh, len, data, match, share, dir, parts, xml, line;
  path = _FCT_ANON_ARGS[0];
  vuln_line = NULL;
  parts = split(path, sep:':', keep:FALSE);
  share = parts[0] + '$';
  xml = parts[1];

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    return NULL;
  }

  fh = CreateFile(
    file:xml,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (fh)
  {
    # This file was a little over 2k. the 4k cap is a sanity check and should be more than enough
    len = GetFileSize(handle:fh);
    if (len > 4096) len = 4096;
    data = ReadFile(handle:fh, length:len, offset:0);

    if (strlen(data) == len)
    {
      foreach line (split(data, sep:'\n', keep:FALSE))
      {
        match = eregmatch(string:line, pattern:'name="SearchExportConverter" active="([^"]+)"');
        if (match[1] == 'yes')
          vuln_line = line;
      }
    }

    CloseFile(handle:fh);
  }

  NetUseDel(close:FALSE);

  return vuln_line;
}


if (get_kb_item('SMB/fast_search_server/prodtype') == 'forSharePoint')
  fast_path = get_kb_item('SMB/fast_search_server/path');

if (isnull(fast_path))
  audit(AUDIT_NOT_INST, 'FAST Search Server for SharePoint');

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);
session_init(socket:soc, hostname:name);

report = NULL;

if (fast_path)
{
  xml_path = fast_path + "\etc\config_data\DocumentProcessor\optionalprocessing.xml";

  if (line = _is_fast_vulnerable(xml_path))
  {
    report +=
      '\nThe workaround for FAST Search Server 2010 for SharePoint is not being' +
      '\nused.  Nessus determined this by reading the following file : ' +
      '\n\n' + xml_path +
      '\n\nwhich contains the following line :' +
      '\n\n' + line;
  }
}

NetUseDel();

if (isnull(report))
  audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  report += '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
