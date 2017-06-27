#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69873);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/12/12 11:41:50 $");

  script_cve_id("CVE-2011-3188");
  script_bugtraq_id(49289);
  script_osvdb_id(75716);

  script_name(english:"Juniper NSM Linux Kernel TCP Sequence Number Generation Issue (PSN-2012-08-688)");
  script_summary(english:"Checks versions of NSM servers");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host has a predictable TCP sequence number generator."
    );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version of one or more Juniper NSM servers running on
the remote host, it is potentially vulnerable to denial of service and
network session hijacking attacks due to a weak IP sequence number
generator."
  );
  # http://kb.juniper.net/InfoCenter/index?page=content&legacyid=PSN-2012-08-688
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63abb75f");
  script_set_attribute(attribute:"solution", value:"Upgrade to NSM version 2011.4s3 / 2012.1 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:netscreen-security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "juniper_nsm_gui_svr_detect.nasl", "juniper_nsm_servers_installed.nasl");
  script_require_keys("Juniper_NSM_VerDetected");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

# Linux specific vuln according to the Vendor's advisory
os = get_kb_item("Host/OS");
if (report_paranoia < 2)
{
  if (!isnull(os) && 'Linux' >!< os) audit(AUDIT_HOST_NOT, 'Linux');
}

kb_base = "Host/NSM/";

get_kb_item_or_exit("Juniper_NSM_VerDetected");

kb_list = make_list();

temp = get_kb_list("Juniper_NSM_GuiSvr/*/build");

if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

temp = get_kb_list("Host/NSM/*/build");
if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

if (isnull(kb_list)) audit(AUDIT_NOT_INST, "Juniper NSM Servers");

report = '';

entry = branch(kb_list);

port = 0;
kb_base = '';

if ("Juniper_NSM_GuiSvr" >< entry)
{
  port = entry - "Juniper_NSM_GuiSvr/" - "/build";
  kb_base = "Juniper_NSM_GuiSvr/" + port + "/";

  report_str1 = "Remote GUI server version : ";
  report_str2 = "Fixed version             : ";
}
else
{
  kb_base = entry - "build";
  if ("guiSvr" >< kb_base)
  {
    report_str1 = "Local GUI server version : ";
    report_str2 = "Fixed version            : ";
  }
  else
  {
    report_str1 = "Local device server version : ";
    report_str2 = "Fixed version               : ";
  }
}

build = get_kb_item_or_exit(entry);
version = get_kb_item_or_exit(kb_base + 'version');

disp_version = version + " (" + build + ")";

# fix : NSM version 2012.1 or later
item = eregmatch(pattern:"^([0-9.]+)", string:version);

# NSM version 2011.4s3 or later (less than build (LGB16z1c17)
if (!isnull(item))
{
  if (
    ver_compare(ver:item[1], fix:'2011.4', strict:FALSE) == -1 ||
    version =~ "^2011.4([sS][1-2])?$"
  )
  {
    report += '\n  ' + report_str1 + disp_version +
              '\n  ' + report_str2 + '2011.4s3 or 2012.1' + '\n';
  }
}

if (report == '') audit(AUDIT_INST_VER_NOT_VULN, "Juniper NSM GUI Server or Device Server");

if (report_verbosity > 0) security_hole(extra:report, port:port);
else security_hole(port);
