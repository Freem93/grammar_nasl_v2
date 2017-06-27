#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-604-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93132);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2015-7576", "CVE-2016-0751", "CVE-2016-0752", "CVE-2016-2097", "CVE-2016-2098", "CVE-2016-6316");
  script_osvdb_id(133586, 133587, 133589, 135126, 135127, 142874);

  script_name(english:"Debian DLA-604-1 : ruby-actionpack-3.2 security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in ruby-actionpack-3.2,
a web-flow and rendering framework and part of Rails :

CVE-2015-7576

A flaw was found in the way the Action Controller component compared
user names and passwords when performing HTTP basic authentication.
Time taken to compare strings could differ depending on input,
possibly allowing a remote attacker to determine valid user names and
passwords using a timing attack.

CVE-2016-0751

A flaw was found in the way the Action Pack component performed MIME
type lookups. Since queries were cached in a global cache of MIME
types, an attacker could use this flaw to grow the cache indefinitely,
potentially resulting in a denial of service.

CVE-2016-0752

A directory traversal flaw was found in the way the Action View
component searched for templates for rendering. If an application
passed untrusted input to the 'render' method, a remote,
unauthenticated attacker could use this flaw to render unexpected
files and, possibly, execute arbitrary code.

CVE-2016-2097

Crafted requests to Action View might result in rendering files from
arbitrary locations, including files beyond the application's view
directory. This vulnerability is the result of an incomplete fix of
CVE-2016-0752. This bug was found by Jyoti Singh and Tobias Kraze from
Makandra.

CVE-2016-2098

If a web applications does not properly sanitize user inputs, an
attacker might control the arguments of the render method in a
controller or a view, resulting in the possibility of executing
arbitrary ruby code. This bug was found by Tobias Kraze from Makandra
and joernchen of Phenoelit.

CVE-2016-6316

Andrew Carpenter of Critical Juncture discovered a cross-site
scripting vulnerability affecting Action View. Text declared as 'HTML
safe' will not have quotes escaped when used as attribute values in
tag helpers.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.6-6+deb7u3.

We recommend that you upgrade your ruby-actionpack-3.2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/08/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby-actionpack-3.2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ruby-actionpack-3.2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails ActionPack Inline ERB Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionpack-3.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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
if (deb_check(release:"7.0", prefix:"ruby-actionpack-3.2", reference:"3.2.6-6+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
