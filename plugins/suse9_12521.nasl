#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42200);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408");

  script_name(english:"SuSE9 Security Update : epiphany (YOU Patch Number 12521)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"seamonkey was updated to version 1.1.18, fixing various security
issues :

  - Moxie Marlinspike reported a heap overflow vulnerability
    in the code that handles regular expressions in
    certificate names. This vulnerability could be used to
    compromise the browser and run arbitrary code by
    presenting a specially crafted certificate to the
    client. This code provided compatibility with the
    non-standard regular expression syntax historically
    supported by Netscape clients and servers. With version
    3.5 Firefox switched to the more limited
    industry-standard wildcard syntax instead and is not
    vulnerable to this flaw. (MFSA 2009-43 / CVE-2009-2404)

  - IOActive security researcher Dan Kaminsky reported a
    mismatch in the treatment of domain names in SSL
    certificates between SSL clients and the Certificate
    Authorities (CA) which issue server certificates. In
    particular, if a malicious person requested a
    certificate for a host name with an invalid null
    character in it most CAs would issue the certificate if
    the requester owned the domain specified after the null,
    while most SSL clients (browsers) ignored that part of
    the name and used the unvalidated part in front of the
    null. This made it possible for attackers to obtain
    certificates that would function for any site they
    wished to target. These certificates could be used to
    intercept and potentially alter encrypted communication
    between the client and a server such as sensitive bank
    account transactions. This vulnerability was
    independently reported to us by researcher Moxie
    Marlinspike who also noted that since Firefox relies on
    SSL to protect the integrity of security updates this
    attack could be used to serve malicious updates. Mozilla
    would like to thank Dan and the Microsoft Vulnerability
    Research team for coordinating a multiple-vendor
    response to this problem. (MFSA 2009-42 / CVE-2009-2408)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2404.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2408.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12521.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"mozilla-1.8_seamonkey_1.1.18-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-devel-1.8_seamonkey_1.1.18-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-dom-inspector-1.8_seamonkey_1.1.18-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-irc-1.8_seamonkey_1.1.18-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-mail-1.8_seamonkey_1.1.18-0.1")) flag++;
if (rpm_check(release:"SUSE9", reference:"mozilla-venkman-1.8_seamonkey_1.1.18-0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
