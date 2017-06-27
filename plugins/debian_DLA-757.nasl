#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-757-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96093);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/27 14:30:01 $");

  script_cve_id("CVE-2016-4412", "CVE-2016-6626", "CVE-2016-9849", "CVE-2016-9850", "CVE-2016-9861", "CVE-2016-9864", "CVE-2016-9865");
  script_osvdb_id(143206, 147892, 147895, 147896, 147903, 147906, 147908);

  script_name(english:"Debian DLA-757-1 : phpmyadmin security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various security issues where found and fixed in phpmyadmin in wheezy.

CVE-2016-4412 / PMASA-2016-57

A user can be tricked in following a link leading to phpMyAdmin, which
after authentication redirects to another malicious site.

CVE-2016-6626 / PMASA-2016-49

In the fix for PMASA-2016-57, we didn't have sufficient checking and
was possible to bypass whitelist.

CVE-2016-9849 / PMASA-2016-60

Username deny rules bypass (AllowRoot & Others) by using Null Byte.

CVE-2016-9850 / PMASA-2016-61

Username matching for the allow/deny rules may result in wrong matches
and detection of the username in the rule due to non-constant
execution time.

CVE-2016-9861 / PMASA-2016-66

In the fix for PMASA-2016-49, we has buggy checks and was possible to
bypass whitelist.

CVE-2016-9864 / PMASA-2016-69

Multiple SQL injection vulnerabilities.

CVE-2016-9865 / PMASA-2016-70

Due to a bug in serialized string parsing, it was possible to bypass
the protection offered by PMA_safeUnserialize() function.

For Debian 7 'Wheezy', these problems have been fixed in version
4:3.4.11.1-2+deb7u7.

We recommend that you upgrade your phpmyadmin packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/phpmyadmin"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected phpmyadmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"phpmyadmin", reference:"4:3.4.11.1-2+deb7u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
