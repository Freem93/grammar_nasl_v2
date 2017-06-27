#TRUSTED 3e8bef159726c48148a086a195680da7ce6ac75eb4258903bfec38776c0fdf5d1d777d76f5c27f250d71e342feff3847e370f9a2b4aa04f4ca6fd097fdfd278a8f243acc036d8b8f01ac5663e8850f70338fe42c7fcb72226d548337fe40632ae69866c8701af1362b0bc56aa523914ef20a28380ddff9cdbdf39a336e5bfaa8161581bd856523508bd9ec8fc8e7ec86dcf911e213d6211c7f03a91669d1d9242b959c069e5a562a6c81b44eba60d77d7f16363eb3fce8c657658ed9f4c3c9696ee0fa0ab741db205991129000484c727ce1356afc8573f43fd07aa0d9f60877f4a01cc9319dee947bdb599262570c1bfee4a65dd8beaf3a0294983a87ce13853b94b4f039eab90914b20d00de8419e4964b03da05e3a4ee8e53b4c985824c8ac363dd3a2b400d808e47788b00476140ca4faba3af3fa217a0eec0fb3a858208f66bc10c81942f91f795782df7877274496dff261a8c1de6e87b15806534c8ee3eae7bed9defb21bf9cdb66ff3ddc722736ea506e24944e9cb61bea0a25ed4be1bbeeaf6497eafe252a9bac4aad13630dc303779b461a383f90634d0d959829800fd541b2531f8ee0d137301a22fd87eca1f48533e2fde8d683887d7a3d9d40bf1fc2189862526131af53144b632948a4e9ad47c10ed59d2f76446300d67998193fe5f574ec182d04dec212f0921be55cca6185cb5e800ab7ee00d7ce193f74c
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("socketpair")) exit(0, "socketpair() not defined.");
if ( NASL_LEVEL < 4000 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(51891);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/10/18");

  script_name(english:"SSL Session Resume Supported");
  script_summary(english:"Checks if caching and resuming SSL sessions is supported.");

  script_set_attribute(attribute:"synopsis", value:"The remote host allows resuming SSL sessions.");
  script_set_attribute(attribute:"description", value:
"This script detects whether a host allows resuming SSL sessions by
performing a full SSL handshake to receive a session ID, and then
reconnecting with the previously used session ID.  If the server
accepts the session ID in the second connection, the server maintains
a cache of sessions that can be resumed.");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("acap_func.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("nntp_func.inc");
include("misc_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");
include("xmpp_func.inc");

global_var comps, disabled, enabled, port;

function initial(encaps)
{
  local_var comp, rec, recs, sock;

  # Create initial session using OpenSSL library.
  sock = open_sock_ssl(port);
  if (!sock)
    return NULL;
  recs = ssl3_handshake(socket:sock, transport:encaps);
  close(sock);

  # Find the ClientHello record.
  rec = ssl_find(
    blob:recs,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_CLIENT_HELLO
  );
  if (isnull(rec))
    return NULL;

  # Cache the list of compression methods for use in the resume
  # ClientHello. We do this because we've observed oddly behaving
  # servers.
  comps = "";
  foreach comp (rec["compression_methods"])
  {
    comps += mkbyte(comp);
  }

  # Find the ServerHello record.
  rec = ssl_find(
    blob:recs,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if (isnull(rec))
    return NULL;

  # Check if the port gave us a session ID.
  if (rec["session_id"] == "")
    return NULL;

  return rec;
}

function resume(cipher, session)
{
  local_var rec, recs, sock;

  # Convert cipher name to its ID.
  if (typeof(cipher) == "int")
    cipher = mkword(cipher);
  else
    cipher = ciphers[cipher];

  # Manually craft a ClientHello with the specified cipher and a
  # session ID given to us previously.
  rec = client_hello(
    version    : mkword(session["version"]),
    sessionid  : session["session_id"],
    cipherspec : cipher,
    compmeths  : comps,
    v2hello    : FALSE
  );
  if (isnull(rec))
    return NULL;

  # Request to resume a previous session.
  sock = open_sock_ssl(port);
  if (!sock)
    return NULL;
  send(socket:sock, data:rec);

  # Receive the target's response.
  recs = "";
  repeat
  {
    rec = recv_ssl(socket:sock);
    if (isnull(rec))
      break;
    recs += rec;
  } until (!socket_pending(sock));
  close(sock);
  if (recs == "")
    return NULL;

  # Find the ServerHello record.
  rec = ssl_find(
    blob:recs,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if (isnull(rec))
    return NULL;

  # Check that the server didn't switch the version.
  if (rec["version"] != session["version"])
    return NULL;

  # Check that we have resumed the session.
  if (rec["session_id"] != session["session_id"])
    return FALSE;

  # Check that the server didn't switch the cipher.
  if (mkword(rec["cipher_spec"]) != cipher)
    return FALSE;

  return TRUE;
}

function resume_different(ciphers, re, session)
{
  local_var cipher, res;

  foreach cipher (ciphers)
  {
    # Skip ciphers that aren't for this protocol.
    if (!isnull(re) && cipher !~ re)
      continue;

    res = resume(cipher:cipher, session:session);

    # Check for errors beyond the server rejecting our resume attempt.
    if (isnull(res))
      return NULL;

    if (res)
      return cipher;
  }

  return NULL;
}

function remember(cipher, encaps, session, type)
{
  local_var id, old;

  if (!port || !encaps)
    return;

  id = hexstr(session["session_id"]);
  old = cipher_name(id:session["cipher_spec"], encaps:encaps);

  set_kb_item(name:"SSL/Resume/" + type, value:port);
  set_kb_item(name:"SSL/Resume/" + type + "/" + port, value:encaps);

  if ( !isnull(id) ) set_kb_item(name:"SSL/Resume/" + type + "/" + port + "/" + encaps + "/Session_ID", value:id);
  if ( !isnull(old) ) set_kb_item(name:"SSL/Resume/" + type + "/" + port + "/" + encaps + "/Initial", value:old);
  if ( !isnull(cipher) ) set_kb_item(name:"SSL/Resume/" + type + "/" + port + "/" + encaps + "/Resumed", value:cipher);
}

function check(encaps, re)
{
  local_var cipher, ciphers_ge, ciphers_lt, different, init_strength;
  local_var session, strength;

  # Check if we can resume with the same cipher.
  session = initial(encaps:encaps);
  if (isnull(session))
    return FALSE;

  if (!resume(cipher:session["cipher_spec"], session:session))
    return FALSE;

  if (port) set_kb_item(name:"SSL/Resume", value:port);
  if (encaps) set_kb_item(name:"SSL/Resume/" + port, value:encaps);

  # Keep track of whether we've successfully resumed with a different cipher,
  # to save us a connection attempt.
  different = FALSE;

  # Check if we can resume with a different disabled cipher.
  session = initial(encaps:encaps);
  if (isnull(session))
    return TRUE;

  cipher = resume_different(ciphers:disabled, session:session, re:re);
  if (!isnull(cipher))
  {
    remember(cipher:cipher, encaps:encaps, session:session, type:"Disabled");
    different = TRUE;
  }

  # Get the strength of the cipher that the server selected.
  init_strength = cipher_strength(session["cipher_spec"], encaps:encaps);

  # We have no good way to force the use of a specific cipher when we
  # use OpenSSL to connect. We don't trust CIPHER_STRENGTH_MAX ciphers
  # to necessarily be that strong, it's an assumption, so we won't
  # perform cipher strength comparisons in that case.
  if (isnull(init_strength) || init_strength == CIPHER_STRENGTH_MAX)
    return TRUE;

  # Create two lists of ciphers: one consisting of ciphers weaker than
  # the one negotiated during the initial connection, and the other
  # not.
  ciphers_lt = make_list();
  ciphers_ge = make_list();
  foreach cipher (enabled)
  {
    # Skip ciphers that aren't for this protocol.
    if (cipher !~ re)
      continue;

    # Skip over the cipher that was negotiated during the initial
    # connection.
    if (getword(blob:ciphers[cipher], pos:0) == session["cipher_spec"])
      continue;

    # Get the strength of this cipher, but skip if it's untrustworthy.
    strength = cipher_strength(cipher, encaps:encaps);
    if (isnull(strength) || strength == CIPHER_STRENGTH_MAX)
      continue;

    if (strength < init_strength)
      ciphers_lt = make_list(ciphers_lt, cipher);
    else
      ciphers_ge = make_list(ciphers_ge, cipher);
  }

  # Check if we can resume with different enabled cipher of lesser strength.
  session = initial(encaps:encaps);
  if (isnull(session))
    return TRUE;

  cipher = resume_different(ciphers:ciphers_lt, session:session);
  if (!isnull(cipher))
  {
    remember(cipher:cipher, encaps:encaps, session:session, type:"Weaker");
    different = TRUE;
  }

  # Check if we can resume with a different enabled cipher of greater or equal
  # strength, but only if we haven't already successfully resumed with a
  # different cipher.
  if (!different)
  {
    session = initial(encaps:encaps);
    if (isnull(session))
      return TRUE;

    cipher = resume_different(ciphers:ciphers_ge, session:session);
    different = (!isnull(cipher));
  }

  if (different)
    remember(cipher:cipher, encaps:encaps, session:session, type:"Different");

  return TRUE;
}

get_kb_item_or_exit("SSL/Supported");

# Get a port to operate on, forking for each one.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Find out if the port is open.
if (!get_port_state(port))
  exit(0, "Port " + port + " is not open.");

# All parameters in SSL are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Decide which encapsulation methods to test.
if (thorough_tests)
{
  supported = make_list(
    ENCAPS_SSLv2,
    ENCAPS_SSLv3,
    ENCAPS_TLSv1,
    COMPAT_ENCAPS_TLSv11,
    COMPAT_ENCAPS_TLSv12
  );
}
else
{
  supported = get_kb_list_or_exit("SSL/Transport/" + port);
}

# Get the list of ciphers enabled on this port.
enabled = get_kb_list_or_exit("SSL/Ciphers/" + port);
enabled = make_list(enabled);
if (max_index(enabled) == 0)
  exit(1, "No supported ciphers were found for port " + port + ".");

# Derive the list of ciphers disabled on this port.
disabled = make_list();
foreach cipher (keys(ciphers))
{
  foreach enabled_cipher (enabled)
  {
    if (cipher == enabled_cipher)
    {
      cipher = NULL;
      break;
    }
  }

  if (cipher)
    disabled = make_list(disabled, cipher);
}

# Check for resume capability in each transport.
resumes = make_list();
foreach encaps (supported)
{
  if (encaps == ENCAPS_SSLv2)
  {
    # Resuming an SSLv2 session requires seeing inside of the final,
    # encrypted record in the handshake process. We can't do this
    # without our own SSLv2 protocol library.
    continue;
  }
  else if (encaps == ENCAPS_SSLv3 && check(encaps:encaps, re:"^SSL3_"))
  {
    resumes = make_list(resumes, "SSLv3");
  }
  else if (encaps == ENCAPS_TLSv1 && check(encaps:encaps, re:"^TLS1_"))
  {
    # For the moment, we can't detect TLSv1 resume support in every
    # case. Since we use OpenSSL for the initial connection, it
    # sends its default list of ciphers. If the fake cipher that
    # indicates secure session resume support is in that cipher
    # list, which depends on the version of OpenSSL, and the server
    # supports it, we won't be able to detect resume support.
    resumes = make_list(resumes, "TLSv1");
  }
  else if (encaps == COMPAT_ENCAPS_TLSv11 || encaps == COMPAT_ENCAPS_TLSv12)
  {
    # This plugin uses the underlying OpenSSL library to create the
    # initial connection to the remote host. For now we have no
    # support available for newer TLS versions.
    continue;
  }
}

if (max_index(resumes) == 0)
  exit(0, "This port does not support resuming SSL / TLS sessions.");

# Report our findings.
resumes = join(resumes, sep:" / ");
report = '\nThis port supports resuming ' + resumes + ' sessions.\n';
security_note(port:port, extra:report);
