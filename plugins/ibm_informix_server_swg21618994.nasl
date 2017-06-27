#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70098);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/25 13:29:26 $");

  script_cve_id("CVE-2012-4857");
  script_bugtraq_id(56857);
  script_osvdb_id(88279);
  script_xref(name:"IAVA", value:"2012-A-0197");

  script_name(english:"IBM Informix Dynamic Server 11.50.x / 11.70.x < 11.70.xC7 RCE (credentialed check)");
  script_summary(english:"Checks IBM Informix Dynamic Server version.");

  script_set_attribute(attribute:"synopsis", value:
"A database server installed on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Informix Dynamic Server installed on the remote
host is 11.50.x or 11.70.x prior to 11.70.xC7. It is, therefore,
affected by a remote code execution vulnerability in the
'genxmlqueryhdr' and genxmlquery' XML functions due to an overflow
condition. An authenticated, remote attacker can exploit this, via a
specially crafted statement, to cause a denial of service condition or
the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21618994");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Informix Dynamic Server version 11.70.xC7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix_dynamic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ibm_informix_server_installed.nasl");
  script_require_keys("installed_sw/IBM Informix Dynamic Server");
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include("install_func.inc");

app_name = 'IBM Informix Dynamic Server';
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

ver   = install['version'];
path  = install['path'];

fix = NULL;

item = eregmatch(pattern:"[cC]([0-9]+)([wW]([0-9]+))?([^0-9]|$)",
                 string:ver);
c_num = 0;
w_num = 0;
if (!isnull(item[1])) c_num = int(item[1]);
if (!isnull(item[2]) && !isnull(item[3])) w_num = int(item[3]);

# 11.50 <= 11.50.xC9W2 (currently no fix for 11.50 branch)
if (ver =~"^11\.50($|\.|[^0-9])" &&
   (c_num < 9 || (c_num == 9 && w_num <= 2)))
  fix = '11.70.xC7';
# 11.70 < 11.70.xC7
else if (ver =~"^11\.70($|\.|[^0-9])" && c_num < 7)
  fix = '11.70.xC7';
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + '\n';

  security_hole(port:port, extra:report);
}
else security_hole(port);
