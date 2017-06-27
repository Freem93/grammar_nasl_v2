#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73186);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2014-2536");
  script_bugtraq_id(66181);
  script_osvdb_id(104113);
  script_xref(name:"MCAFEE-SB", value:"SB10066");

  script_name(english:"McAfee Cloud Single Sign On < 4.0.1 Information Disclosure (SB10066) (McAfee Linux OS)");
  script_summary(english:"Checks version of MCSSO collected via SSH");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"A version of McAfee Cloud Single Sign On (MCSSO) prior to 4.0.1 is
installed on the remote host. It is, therefore, affected by an
information disclosure vulnerability due to a failure to sanitize
user-supplied input, resulting in a potential directory traversal. An
attacker could potentially exploit this vulnerability to download
arbitrary files, including one containing a hash of the product
administrator's password.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-050/");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10066");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:cloud_single_sign_on");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/McAfeeLinux/release", "Host/McAfeeLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/McAfeeLinux/release");
if (isnull(release) || "MLOS" >!< release) audit(AUDIT_OS_NOT, "McAfee Linux OS");
if (!get_kb_item("Host/McAfeeLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;
if (rpm_check(release:"MLOS2", reference:"mcsso-4.0.1-197.mlos2.mcsso")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
