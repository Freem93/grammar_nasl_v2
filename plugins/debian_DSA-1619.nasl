#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1619. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33739);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/07 14:59:56 $");

  script_cve_id("CVE-2008-1447", "CVE-2008-4099", "CVE-2008-4194");
  script_bugtraq_id(30131);
  script_osvdb_id(47232, 47916, 47926, 47927, 48245);
  script_xref(name:"DSA", value:"1619");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"Debian DSA-1619-1 : python-dns - DNS response spoofing");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple weaknesses have been identified in PyDNS, a DNS client
implementation for the Python language. Dan Kaminsky identified a
practical vector of DNS response spoofing and cache poisoning,
exploiting the limited entropy in a DNS transaction ID and lack of UDP
source port randomization in many DNS implementations. Scott Kitterman
noted that python-dns is vulnerable to this predictability, as it
randomizes neither its transaction ID nor its source port. Taken
together, this lack of entropy leaves applications using python-dns to
perform DNS queries highly susceptible to response forgery.

The Common Vulnerabilities and Exposures project identifies this class
of weakness as CVE-2008-1447 and this specific instance in PyDNS as
CVE-2008-4099."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=490217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1619"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python-dns package.

For the stable distribution (etch), these problems have been fixed in
version 2.3.0-5.2+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-dns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/28");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"python-dns", reference:"2.3.0-5.2+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
