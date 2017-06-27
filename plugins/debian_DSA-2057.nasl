#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2057. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46832);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850");
  script_bugtraq_id(40100, 40106, 40109, 40257);
  script_xref(name:"DSA", value:"2057");

  script_name(english:"Debian DSA-2057-1 : mysql-dfsg-5.0 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the MySQL database
server. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2010-1626
    MySQL allows local users to delete the data and index
    files of another user's MyISAM table via a symlink
    attack in conjunction with the DROP TABLE command.

  - CVE-2010-1848
    MySQL failed to check the table name argument of a
    COM_FIELD_LIST command packet for validity and
    compliance to acceptable table name standards. This
    allows an authenticated user with SELECT privileges on
    one table to obtain the field definitions of any table
    in all other databases and potentially of other MySQL
    instances accessible from the server's file system.

  - CVE-2010-1849
    MySQL could be tricked to read packets indefinitely if
    it received a packet larger than the maximum size of one
    packet. This results in high CPU usage and thus denial
    of service conditions.

  - CVE-2010-1850
    MySQL was susceptible to a buffer-overflow attack due to
    a failure to perform bounds checking on the table name
    argument of a COM_FIELD_LIST command packet. By sending
    long data for the table name, a buffer is overflown,
    which could be exploited by an authenticated user to
    inject malicious code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2057"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql-dfsg-5.0 package.

For the stable distribution (lenny), these problems have been fixed in
version 5.0.51a-24+lenny4"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg-5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/08");
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
if (deb_check(release:"5.0", prefix:"libmysqlclient15-dev", reference:"5.0.51a-24+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libmysqlclient15off", reference:"5.0.51a-24+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-client", reference:"5.0.51a-24+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-client-5.0", reference:"5.0.51a-24+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-common", reference:"5.0.51a-24+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-server", reference:"5.0.51a-24+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"mysql-server-5.0", reference:"5.0.51a-24+lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
