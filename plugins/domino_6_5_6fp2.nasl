#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27856);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2007-3510", "CVE-2007-5924");
  script_bugtraq_id(26176, 26298);
  script_osvdb_id(39720, 40953);

  script_name(english:"IBM Lotus Domino < 6.5.6 FP2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Lotus Domino");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Lotus Domino on the remote host appears to be older
than 6.5.6 FP2.  According to IBM, such versions may be affected by
several security issues, depending on the specific version and its
configuration.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21263871");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27010980");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lotus Domino 6.5.6 FP2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79, 119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("domino_installed.nasl");
  script_require_keys("Domino/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# There's a problem if the version is < 6.5.6 FP2.
version = get_kb_item_or_exit("Domino/Version");
if (egrep(pattern:"^6\.5\.([0-5]($|[^0-9])|6($| FP1$))", string:version))
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.5.6 FP2\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since Domino "+version+" is installed.");
