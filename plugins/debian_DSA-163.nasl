#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-163. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15000);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/08/14 14:19:28 $");

  script_cve_id("CVE-2002-0738");
  script_bugtraq_id(4546);
  script_osvdb_id(5121);
  script_xref(name:"DSA", value:"163");

  script_name(english:"Debian DSA-163-1 : mhonarc - XSS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jason Molenda and Hiromitsu Takagi foundways to exploit cross site
scripting bugs in mhonarc, a mail to HTML converter. When processing
maliciously crafted mails of type text/html mhonarc does not
deactivate all scripting parts properly. This is fixed in upstream
version 2.5.3.

If you are worried about security, it is recommended that you disable
support of text/html messages in your mail archives. There is no
guarantee that the mhtxthtml.pl library is robust enough to eliminate
all possible exploits that can occur with HTML data.

To exclude HTML data, you can use the MIMEEXCS resource. For example :

    <MIMEExcs> text/html text/x-html </MIMEExcs>

The type 'text/x-html' is probably not used any more, but is good to
include it, just-in-case.

If you are concerned that this could block out the entire contents of
some messages, then you could do the following instead :

    <MIMEFilters> text/html; m2h_text_plain::filter; mhtxtplain.pl
    text/x-html; m2h_text_plain::filter; mhtxtplain.pl </MIMEFilters>

This treats the HTML as text/plain.

The above problems have been fixed in version 2.5.2-1.1 for the
current stable distribution (woody), in version 2.4.4-1.1 for the old
stable distribution (potato) and in version 2.5.11-1 for the unstable
distribution (sid)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://online.securityfocus.com/archive/1/268455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-163"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the mhonarc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mhonarc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"mhonarc", reference:"2.4.4-1.1")) flag++;
if (deb_check(release:"3.0", prefix:"mhonarc", reference:"2.5.2-1.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
