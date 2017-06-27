#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88044);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

  script_cve_id("CVE-2014-0107");
  script_bugtraq_id(66397);
  script_osvdb_id(104942);

  script_name(english:"Oracle WebCenter Sites Apache Xalan-Java Library Security Bypass (January 2016 CPU)");
  script_summary(english:"Checks for January 2016 CPU patches.");

  script_set_attribute(attribute:"synopsis", value:
"The website content management system installed on the remote host is
affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version Oracle WebCenter Sites installed on the remote host is
missing a security patch from the January 2016 Critical Patch Update
(CPU). It is, therefore, affected by a security bypass vulnerability
in the Apache Xalan-Java library due to a failure to properly restrict
access to certain properties when FEATURE_SECURE_PROCESSING is
enabled. A remote attacker can exploit this to bypass restrictions and
load arbitrary classes or access external resources.");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efa5c48c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies('oracle_webcenter_sites_installed.nbin');
  script_require_keys('SMB/WebCenter_Sites/Installed');
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

port = kb_smb_transport();

get_kb_item_or_exit('SMB/WebCenter_Sites/Installed');

versions = get_kb_list('SMB/WebCenter_Sites/*/Version');
if (isnull(versions)) exit(1, 'Unable to obtain a version list for Oracle WebCenter Sites.');

report = '';

foreach key (keys(versions))
{
  fix = '';

  version = versions[key];
  revision = get_kb_item(key - '/Version' + '/Revision');
  path = get_kb_item(key - '/Version' + '/Path');

  if (isnull(version) || isnull(revision)) continue;

  # Patch 22174981 - 11.1.1.8.0 < Revision 180102
  if (version =~ "^11\.1\.1\.8\.0$" && revision < 180102)
    fix = '\n  Fixed revision : 180102' +
          '\n  Required patch : 22174981';

  # Patch 21834997 - 7.6.2 < Revision 179663
  if (version =~ "^7\.6\.2(\.|$)" && revision < 179663)
    fix = '\n  Fixed revision : 179663' +
          '\n  Required patch : 21834997';

  if (fix != '')
  {
    if (!isnull(path)) report += '\n  Path           : ' + path;
    report += '\n  Version        : ' + version +
              '\n  Revision       : ' + revision +
              fix + '\n';
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Oracle WebCenter Sites");
