#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55651);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/01/23 17:41:30 $");

  script_bugtraq_id(47359);

  script_name(english:"SAP GUI saplogon.ini File Buffer Overflow (Note 1504547)");
  script_summary(english:"Checks the version of SAP GUI.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is susceptible to a buffer overflow.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of SAP GUI that is reportedly
affected by a buffer overflow vulnerability. By convincing a user to
open a specially crafted 'saplogon.ini' file, an attacker may be able
to execute arbitrary code with the credentials of the user.");

  script_set_attribute(attribute:"see_also", value:"http://dsecrg.com/pages/vul/show.php?id=317");
  script_set_attribute(attribute:"see_also", value:"https://service.sap.com/sap/support/notes/1504547");

  script_set_attribute(attribute:"solution", value:
"Upgrade to SAP GUI version 7.10 SP21 / 7.20 SP3 or higher.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:gui");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("sap_gui_detect.nasl");
  script_require_keys("SMB/SAP_GUI/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Pull the installation information from the KB.
base = get_kb_item_or_exit("SMB/SAP_GUI/Path");
ver = get_kb_item_or_exit("SMB/SAP_GUI/Version");

iver = split(ver, sep:".", keep:FALSE);

# Determine if the version is vulnerable.
if (iver[0] == 7100)
  fix = "7100.4.21.8943";
else if (iver[0] == 7200)
  fix = "7200.1.3.8945";

if (isnull(fix) || ver_compare(ver:ver, fix:fix) >= 0)
  exit(0, "The SAP GUI " + ver + " install is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + base +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
else security_hole(get_kb_item("SMB/transport"));
