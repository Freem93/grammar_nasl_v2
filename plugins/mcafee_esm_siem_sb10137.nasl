#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90424);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2015-8024");
  script_bugtraq_id(85542);
  script_osvdb_id(129549);
  script_xref(name:"IAVA", value:"2016-A-0084");
  script_xref(name:"MCAFEE-SB", value:"SB10137");

  script_name(english:"McAfee Security Information and Event Management 9.3.x < 9.3.2.19 / 9.4.x < 9.4.2.9 / 9.5.x < 9.5.0.8 Authentication Bypass (SB10137)");
  script_summary(english:"Checks the product version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the McAfee Security
Information and Event Management (SIEM) application installed on the
remote host is 9.3.x prior to 9.3.2.19, 9.4.x prior to 9.4.2.9, or
9.5.x prior to 9.5.0.8. It is therefore, affected by an authentication
bypass vulnerability in the Enterprise Security Manager (ESM),
Enterprise Security Manager/Log Manager (ESMLM), and Enterprise
Security Manager/Receiver (ESMREC) components due to improper
sanitization of usernames. This vulnerability occurs when these
components are configured to use Active Directory or LDAP as
authentication sources. A remote attacker can exploit this issue, via
a specially crafted username, to log on to the system using any
password.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB83418");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10137");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version according to the McAfee
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:mcafee_enterprise_security_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_esm_siem_detect.nbin");
  script_require_keys("Host/McAfee ESM/Display Version", "Host/McAfee ESM/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "McAfee Entersprise Security Manager";
version  = get_kb_item_or_exit("Host/McAfee ESM/Version");
display_version  = get_kb_item_or_exit("Host/McAfee ESM/Display Version");
report = "";

if(
  ( version =~ "^9\.3" && (ver_compare(ver:version, fix:"9.3.2.19", strict:FALSE) < 0)) ||
  ( version =~ "^9\.4" && (ver_compare(ver:version, fix:"9.4.2.9", strict:FALSE) < 0) ) ||
  ( version =~ "^9\.5" && (ver_compare(ver:version, fix:"9.5.0.8", strict:FALSE) < 0) )
  )
{
  if(version =~ "^9\.3") fix = "9.3.2 MR19";
  if(version =~ "^9\.4") fix = "9.4.2 MR9";
  if(version =~ "^9\.5") fix = "9.5.0 MR8";

  report += '\n  Installed Version : ' + display_version +
            '\n  Fixed Version     : ' + fix + '\n\n';

    security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "McAfee Enterprise Security Manager", display_version);
