#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:189. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(67134);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/05/22 11:11:55 $");

  script_cve_id("CVE-2013-2173", "CVE-2013-2199", "CVE-2013-2200", "CVE-2013-2201", "CVE-2013-2202", "CVE-2013-2203", "CVE-2013-2204", "CVE-2013-2205");
  script_bugtraq_id(60477, 60757, 60758, 60759, 60770, 60775, 60781, 60825);
  script_xref(name:"MDVSA", value:"2013:189");

  script_name(english:"Mandriva Linux Security Advisory : wordpress (MDVSA-2013:189)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wordpress package fixes security vulnerabilities :

A denial of service flaw was found in the way Wordpress, a blog tool
and publishing platform, performed hash computation when checking
password for password protected blog posts. A remote attacker could
provide a specially- crafted input that, when processed by the
password checking mechanism of Wordpress would lead to excessive CPU
consumption (CVE-2013-2173).

Inadequate SSRF protection for HTTP requests where the user can
provide a URL can allow for attacks against the intranet and other
sites. This is a continuation of work related to CVE-2013-0235, which
was specific to SSRF in pingback requests and was fixed in 3.5.1
(CVE-2013-2199).

Inadequate checking of a user's capabilities could allow them to
publish posts when their user role should not allow for it; and to
assign posts to other authors (CVE-2013-2200).

Inadequate escaping allowed an administrator to trigger a cross-site
scripting vulnerability through the uploading of media files and
plugins (CVE-2013-2201).

The processing of an oEmbed response is vulnerable to an XXE
(CVE-2013-2202).

If the uploads directory is not writable, error message data returned
via XHR will include a full path to the directory (CVE-2013-2203).

Content Spoofing in the MoxieCode (TinyMCE) MoxiePlayer project
(CVE-2013-2204).

Cross-domain XSS in SWFUpload (CVE-2013-2205)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2013-0198.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", reference:"wordpress-3.5.2-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
