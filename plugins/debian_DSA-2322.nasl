#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2322. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56444);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2010-4567", "CVE-2010-4568", "CVE-2010-4572", "CVE-2011-0046", "CVE-2011-0048", "CVE-2011-2379", "CVE-2011-2380", "CVE-2011-2381", "CVE-2011-2978", "CVE-2011-2979");
  script_bugtraq_id(45982, 49042);
  script_osvdb_id(70699, 70700, 70703, 70704, 70705, 70706, 70707, 70708, 70709, 70710, 74297, 74298, 74299, 74300, 74301);
  script_xref(name:"DSA", value:"2322");

  script_name(english:"Debian DSA-2322-1 : bugzilla - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Bugzilla, a web-based bug
tracking system.

  - CVE-2010-4572
    By inserting particular strings into certain URLs, it
    was possible to inject both headers and content to any
    browser.

  - CVE-2010-4567, CVE-2011-0048
    Bugzilla has a 'URL' field that can contain several
    types of URL, including 'javascript:' and 'data:' URLs.
    However, it does not make 'javascript:' and 'data:' URLs
    into clickable links, to protect against cross-site
    scripting attacks or other attacks. It was possible to
    bypass this protection by adding spaces into the URL in
    places that Bugzilla did not expect them. Also,
    'javascript:' and'data:' links were always shown as
    clickable to logged-out users.

  - CVE-2010-4568
    It was possible for a user to gain unauthorized access
    to any Bugzilla account in a very short amount of time
    (short enough that the attack is highly effective).

  - CVE-2011-0046
    Various pages were vulnerable to Cross-Site Request
    Forgery attacks. Most of these issues are not as serious
    as previous CSRF vulnerabilities.

  - CVE-2011-2978
    When a user changes his email address, Bugzilla trusts a
    user-modifiable field for obtaining the current e-mail
    address to send a confirmation message to. If an
    attacker has access to the session of another user (for
    example, if that user left their browser window open in
    a public place), the attacker could alter this field to
    cause the email-change notification to go to their own
    address. This means that the user would not be notified
    that his account had its email address changed by the
    attacker.

  - CVE-2011-2381
    For flagmails only, attachment descriptions with a
    newline in them could lead to the injection of crafted
    headers in email notifications when an attachment flag
    is edited.

  - CVE-2011-2379
    Bugzilla uses an alternate host for attachments when
    viewing them in raw format to prevent cross-site
    scripting attacks. This alternate host is now also used
    when viewing patches in 'Raw Unified' mode because
    Internet Explorer 8 and older, and Safari before 5.0.6
    do content sniffing, which could lead to the execution
    of malicious code.

  - CVE-2011-2380, CVE-2011-2979
    Normally, a group name is confidential and is only
    visible to members of the group, and to non-members if
    the group is used in bugs. By crafting the URL when
    creating or editing a bug, it was possible to guess if a
    group existed or not, even for groups which weren't used
    in bugs and so which were supposed to remain
    confidential."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/bugzilla"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2322"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bugzilla packages.

For the oldstable distribution (lenny), it has not been practical to
backport patches to fix these bugs. Users of bugzilla on lenny are
strongly advised to upgrade to the version in the squeeze
distribution.

For the stable distribution (squeeze), these problems have been fixed
in version 3.6.2.0-4.4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"bugzilla3", reference:"3.6.2.0-4.4")) flag++;
if (deb_check(release:"6.0", prefix:"bugzilla3-doc", reference:"3.6.2.0-4.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
