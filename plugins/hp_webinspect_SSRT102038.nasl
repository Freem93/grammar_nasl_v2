#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84194);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id("CVE-2015-2125");
  script_bugtraq_id(75036);
  script_osvdb_id(122947);
  script_xref(name:"HP", value:"HPSBGN03343");
  script_xref(name:"HP", value:"SSRT102038");
  script_xref(name:"HP", value:"emr_na-c04695307");
  script_xref(name:"EDB-ID", value:"37250");
  
  script_name(english:"HP WebInspect XXE Unauthorized Information Disclosure");
  script_summary(english:"Checks the version of HP WebInspect.");

  script_set_attribute(attribute:"synopsis", value:
"A web security application on the remote host is affected by an
unauthorized information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP WebInspect installed on the remote Windows host is
affected by an unauthorized information disclosure vulnerability due
to an XML external entity injection flaw that is triggered during the
parsing of XML data. A remote attacker can exploit this, via a
malicious website scanned by HP WebInspect, to read arbitrary system
files.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04695307
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94288510");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/37250/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/535683");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP WebInspect version 10.40.282.10 (10.4 Software Update
1) or later.

Note that HP has not yet made this update generally available via
SmartUpdate, and you must contact HP Support directly for the fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:web_inspect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_webinspect_installed.nbin");
  script_require_keys("installed_sw/HP WebInspect");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'HP WebInspect';
install = get_single_install(app_name:appname,exit_if_unknown_ver:TRUE);
version = install["version"];
path    = install["path"];
port    = get_kb_item("SMB/transport");
if (!port) port = 445;

if( # 10.40.282.10 Confirmed fix by HP
   ver_compare(ver:version, fix:"10.40.282.10", strict:FALSE) <  0 &&
   ver_compare(ver:version, fix:"7.0.0.0",      strict:FALSE) >= 0
)
{
  report = NULL;
  if(report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 10.40.282.10\n';
  }
  security_warning(port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
