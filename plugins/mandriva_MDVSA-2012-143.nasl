#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:143. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61988);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/01 00:27:16 $");

  script_cve_id("CVE-2012-3442", "CVE-2012-3443", "CVE-2012-3444");
  script_bugtraq_id(54742);
  script_xref(name:"MDVSA", value:"2012:143");

  script_name(english:"Mandriva Linux Security Advisory : python-django (MDVSA-2012:143)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in
python-django :

The (1) django.http.HttpResponseRedirect and (2)
django.http.HttpResponsePermanentRedirect classes in Django before
1.3.2 and 1.4.x before 1.4.1 do not validate the scheme of a redirect
target, which might allow remote attackers to conduct cross-site
scripting (XSS) attacks via a data: URL (CVE-2012-3442).

The django.forms.ImageField class in the form system in Django before
1.3.2 and 1.4.x before 1.4.1 completely decompresses image data during
image validation, which allows remote attackers to cause a denial of
service (memory consumption) by uploading an image file
(CVE-2012-3443).

The get_image_dimensions function in the image-handling functionality
in Django before 1.3.2 and 1.4.x before 1.4.1 uses a constant chunk
size in all attempts to determine dimensions, which allows remote
attackers to cause a denial of service (process or thread consumption)
via a large TIFF image (CVE-2012-3444).

The updated packages have been upgraded to the 1.3.3 version which is
not vulnerable to these issues."
  );
  # https://www.djangoproject.com/weblog/2012/jul/30/security-releases-issued/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27d596e2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", reference:"python-django-1.3.3-0.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
