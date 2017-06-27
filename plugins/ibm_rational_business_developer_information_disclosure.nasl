#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66307);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/07/01 21:36:51 $");

  script_cve_id("CVE-2012-3319");
  script_bugtraq_id(55718);
  script_osvdb_id(85867);
  script_xref(name:"IAVB", value:"2012-B-0097");

  script_name(english:"IBM Rational Business Developer 8.x < 8.0.1.4 Information Disclosure");
  script_summary(english:"Checks version of IBM Rational Business Developer");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a development application installed that is 
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Rational Business Developer installed on the 
remote Windows host is affected by an unspecified vulnerability
that could lead to potentially sensitive information being revealed
to an untrusted client.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21612314");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational Business Developer 8.0.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_business_developer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ibm_rational_business_developer_installed.nasl");
  script_require_keys("SMB/IBM Rational Business Developer/Path", "SMB/IBM Rational Business Developer/Version");
  
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

path = get_kb_item_or_exit('SMB/IBM Rational Business Developer/Path');
version = get_kb_item_or_exit('SMB/IBM Rational Business Developer/Version');

if (version =~ '^8\\.0' && ver_compare(ver:version, fix:'8.0.1.4', strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.1.4\n';
    security_warning(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_warning(port:get_kb_item('SMB/transport'));
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'IBM Rational Business Developer', version, path);
