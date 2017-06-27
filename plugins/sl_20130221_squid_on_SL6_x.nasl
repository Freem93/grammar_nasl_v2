#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64960);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/01 11:58:42 $");

  script_cve_id("CVE-2012-5643");

  script_name(english:"Scientific Linux Security Update : squid on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service flaw was found in the way the Squid Cache Manager
processed certain requests. A remote attacker who is able to access
the Cache Manager CGI could use this flaw to cause Squid to consume an
excessive amount of memory. (CVE-2012-5643)

This update also fixes the following bugs :

  - Due to a bug in the
    ConnStateData::noteMoreBodySpaceAvailable() function,
    child processes of Squid terminated upon encountering a
    failed assertion. An upstream patch has been provided
    and Squid child processes no longer terminate.

  - Due to an upstream patch, which renamed the HTTP header
    controlling persistent connections from
    'Proxy-Connection' to 'Connection', the NTLM pass-
    through authentication does not work, thus preventing
    login. This update adds the new 'http10' option to the
    squid.conf file, which can be used to enable the change
    in the patch. This option is set to 'off' by default.
    When set to 'on', the NTLM pass-through authentication
    works properly, thus allowing login attempts to succeed.

  - When the IPv6 protocol was disabled and Squid tried to
    handle an HTTP GET request containing an IPv6 address,
    the Squid child process terminated due to signal 6. This
    bug has been fixed and such requests are now handled as
    expected.

  - The old 'stale if hit' logic did not account for cases
    where the stored stale response became fresh due to a
    successful re-validation with the origin server.
    Consequently, incorrect warning messages were returned.
    Now, Squid no longer marks elements as stale in the
    described scenario.

  - When squid packages were installed before samba-winbind,
    the wbpriv group did not include Squid. Consequently,
    NTLM authentication calls failed. Now, Squid correctly
    adds itself into the wbpriv group if samba-winbind is
    installed before Squid, thus fixing this bug.

  - In FIPS mode, Squid was using private MD5 hash functions
    for user authentication and network access. As MD5 is
    incompatible with FIPS mode, Squid could fail to start.
    This update limits the use of the private MD5 functions
    to local disk file hash identifiers, thus allowing Squid
    to work in FIPS mode.

  - Under high system load, the squid process could
    terminate unexpectedly with a segmentation fault during
    reboot. This update provides better memory handling
    during reboot, thus fixing this bug.

  - Squid incorrectly set the timeout limit for client HTTP
    connections with the value for server-side connections,
    which is much higher, thus creating unnecessary delays.
    With this update, Squid uses a proper value for the
    client timeout limit.

  - Squid did not properly release allocated memory when
    generating error page contents, which caused memory
    leaks. Consequently, the Squid proxy server consumed a
    lot of memory within a short time period. This update
    fixes this memory leak.

  - Squid did not pass the ident value to a URL rewriter
    that was configured using the 'url_rewrite_program'
    directive. Consequently, the URL rewriter received the
    dash character ('') as the user value instead of the
    correct user name. Now, the URL rewriter receives the
    correct user name in the described scenario.

  - Squid, used as a transparent proxy, can only handle the
    HTTP protocol. Previously, it was possible to define a
    URL in which the access protocol contained the asterisk
    character (*) or an unknown protocol namespace URI.
    Consequently, an 'Invalid URL' error message was logged
    to access.log during reload. This update ensures that
    'http://' is always used in transparent proxy URLs, and
    the error message is no longer logged in this scenario.

After installing this update, the squid service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=4163
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?505d773c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid and / or squid-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"squid-3.1.10-16.el6")) flag++;
if (rpm_check(release:"SL6", reference:"squid-debuginfo-3.1.10-16.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
