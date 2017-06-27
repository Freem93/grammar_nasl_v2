#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2415. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58078);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:31:57 $");

  script_cve_id("CVE-2011-1761", "CVE-2011-2911", "CVE-2011-2912", "CVE-2011-2913", "CVE-2011-2914", "CVE-2011-2915");
  script_bugtraq_id(47624, 48979);
  script_osvdb_id(72157, 74208, 74209, 74210, 74211);
  script_xref(name:"DSA", value:"2415");

  script_name(english:"Debian DSA-2415-1 : libmodplug - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities that can lead to the execution of arbitrary
code have been discovered in libmodplug, a library for MOD music based
on ModPlug. The Common Vulnerabilities and Exposures project
identifies the following issues :

  - CVE-2011-1761
    epiphant discovered that the abc file parser is
    vulnerable to several stack-based buffer overflows that
    potentially lead to the execution of arbitrary code.

  - CVE-2011-2911
    Hossein Lotfi of Secunia discovered that the
    CSoundFile::ReadWav function is vulnerable to an integer
    overflow which leads to a heap-based buffer overflow. An
    attacker can exploit this flaw to potentially execute
    arbitrary code by tricking a victim into opening crafted
    WAV files.

  - CVE-2011-2912
    Hossein Lotfi of Secunia discovered that the
    CSoundFile::ReadS3M function is vulnerable to a
    stack-based buffer overflow. An attacker can exploit
    this flaw to potentially execute arbitrary code by
    tricking a victim into opening crafted S3M files.

  - CVE-2011-2913
    Hossein Lotfi of Secunia discovered that the
    CSoundFile::ReadAMS function suffers from an off-by-one
    vulnerability that leads to memory corruption. An
    attacker can exploit this flaw to potentially execute
    arbitrary code by tricking a victim into opening crafted
    AMS files.

  - CVE-2011-2914
    It was discovered that the CSoundFile::ReadDSM function
    suffers from an off-by-one vulnerability that leads to
    memory corruption. An attacker can exploit this flaw to
    potentially execute arbitrary code by tricking a victim
    into opening crafted DSM files.

  - CVE-2011-2915
    It was discovered that the CSoundFile::ReadAMS2 function
    suffers from an off-by-one vulnerability that leads to
    memory corruption. An attacker can exploit this flaw to
    potentially execute arbitrary code by tricking a victim
    into opening crafted AMS files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libmodplug"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2415"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libmodplug packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1:0.8.8.1-1+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmodplug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libmodplug-dev", reference:"1:0.8.8.1-1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libmodplug1", reference:"1:0.8.8.1-1+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
