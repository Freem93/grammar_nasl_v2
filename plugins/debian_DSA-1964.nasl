#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1964. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44829);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2009-4034", "CVE-2009-4136");
  script_bugtraq_id(37333, 37334);
  script_osvdb_id(61038, 61039);
  script_xref(name:"DSA", value:"1964");

  script_name(english:"Debian DSA-1964-1 : postgresql-7.4, postgresql-8.1, postgresql-8.3 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in PostgreSQL, a database
server. The Common Vulnerabilities and Exposures project identifies
the following problems :

It was discovered that PostgreSQL did not properly verify the Common
Name attribute in X.509 certificates, enabling attackers to bypass the
(optional) TLS protection on client-server connections, by relying on
a certificate from a trusted CA which contains an embedded NUL byte in
the Common Name (CVE-2009-4034 ).

Authenticated database users could elevate their privileges by
creating specially crafted index functions (CVE-2009-4136 ).

The following matrix shows fixed source package versions for the
respective distributions.

                    oldstable/etch    stable/lenny      testing/unstable  
  postgresql-7.4    7.4.27-0etch1                                         
  postgresql-8.1    8.1.19-0etch1                                         
  postgresql-8.3                      8.3.9-0lenny1     8.3.9-1           
  postgresql-8.4                                        8.4.2-1           
In addition to these security fixes, the updates contain reliability
improvements and fix other defects."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1964"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the PostgreSQL packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libecpg-compat2", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libecpg-dev", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libecpg5", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpgtypes2", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpq-dev", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libpq4", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-7.4", reference:"7.4.27-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-8.1", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-client-7.4", reference:"7.4.27-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-client-8.1", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-contrib-7.4", reference:"7.4.27-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-contrib-8.1", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-doc-7.4", reference:"7.4.27-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-doc-8.1", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-plperl-7.4", reference:"7.4.27-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-plperl-8.1", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-plpython-7.4", reference:"7.4.27-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-plpython-8.1", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-pltcl-7.4", reference:"7.4.27-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-pltcl-8.1", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-server-dev-7.4", reference:"7.4.27-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"postgresql-server-dev-8.1", reference:"8.1.19-0etch1")) flag++;
if (deb_check(release:"5.0", prefix:"libecpg-compat3", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libecpg-dev", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libecpg6", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpgtypes3", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpq-dev", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libpq5", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-8.3", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-client", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-client-8.3", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-contrib", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-contrib-8.3", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-doc", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-doc-8.3", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-plperl-8.3", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-plpython-8.3", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-pltcl-8.3", reference:"8.3.9-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-server-dev-8.3", reference:"8.3.9-0lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
