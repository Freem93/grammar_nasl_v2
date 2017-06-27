#TRUSTED 794ae69c0b1707b986ba6f0360fbd76946ca66f58aa37ff7f820ac96b640c52153ab649067070c602f6eee64e8dc6e9efc9b2fdcdd437ce4b032486f35348ba38b1164e45b30c3bc53284c763eda54468cb4c3b2da9d3db2c2eb5c6943f8037b85f82d90584f69885218bda8f3bc61f3a671b68f97df543aec3d8e2e95c686ca2322511bf93a300a007ca2a20720980930f0e0f8afb2391bd08471ad1b79cfc247c53bbf28f7245778280928a5c07ad69ec066b166581313960e499a0ac6d90489684eceb0a22da96d215de9832b716998a5fbf689f530b32f3c5dceb09b443f5e5f9f2f2280dc3fbe9c4d773291bb3a596dae03ea65cd10dfabd0ff0c2ccc4cfb375f0e322be45adf0edb4d4a3c9a07105b052017f08d6d9ecf71bb6252c0a9e65a0f72da7b8c8c4619a56b9f7a072cc15a2c808e62483938ac825eb0e5115e726e0af505a0384a0a21c5ae223c4c5f9b4e6c5cc466ee47d448166369cc43aba1e846fb85cb5aca7b5d9ca096f2512a9eba0af3d7833aa353c512dad1bad113679a86f14071684fd89b0fc07c2602f8324b274d8d1bd840967be9c6c9c85f017450c7107deaa43f8546542354fdd4f8814021ea63509da394d719bd1f1cf8e124797668176d5fde15a19de316a17aa9a0f5032e7586a23c4729db3cd77c8b309e42067e8bbe277c0bda20bf822e5c4b6e644d915fbd470924b34160bebaeff7
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# string_printf.inc
#
# Revision: 1.2
#

include("obj.inc");
include("path.inc");

global_var
  _FORMAT_STATE_NEW,
  _FORMAT_STATE_PERCENT,
  _FORMAT_STATE_KEYWORD,
  _FORMAT_STATE_FLAGS,
  _FORMAT_STATE_WIDTH,
  _FORMAT_STATE_PRECISION,
  _FORMAT_STATE_TYPE,
  _FORMAT_STATE_READY,
  _FORMAT_STATE_DONE;

_FORMAT_STATE_NEW       = 0;
_FORMAT_STATE_PERCENT   = 1;
_FORMAT_STATE_KEYWORD   = 2;
_FORMAT_STATE_FLAGS     = 3;
_FORMAT_STATE_WIDTH     = 4;
_FORMAT_STATE_PRECISION = 5;
_FORMAT_STATE_TYPE      = 6;
_FORMAT_STATE_READY     = 7;
_FORMAT_STATE_DONE      = 8;

##
# Internal function for the printf suite of functions. Handles
# choosing the source of data for the current format specifier.
#
# @param args  The array of arguments passed to sprintf.
# @param state The current state table.
#
# @return The data to be used.
##
function _get_printf_arg(args, state)
{
  local_var arg;

  if (max_index(state["keywords"]) > 1)
    arg = path_get(args:state["keywords"]);
  else
    arg = args[state["args_pos"]];

  return arg;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where the string is being read, as normal.
#
# If the string ends, move to the DONE state.
#
# If the string contains a '%' (a format indicator), go to the PERCENT state.
#
# Everything else, just add to the string.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_new(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c == "%")
  {
    state["state"] = _FORMAT_STATE_PERCENT;
    state["format_pos"]++;
  }
  else
  {
    state["result"] += c;
    state["format_pos"]++;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where a percent sign has just been read and we're processing the
# next character. This state is only necessary because of the potential '%%'
# construct (which adds a single percent sign to the string).
#
# If the string ends, add the '%' to the string and move to the DONE state.
#
# If the next character is a '%', add a single '%' to the string and return to
# the NEW state.
#
# If the next character is a '(', go to the KEYWORD state.
#
# If the next character is a letter, go to the TYPE state.
#
# If the next character is a number, go to the WIDTH state.
#
# Everything else, go to FLAGS.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_percent(c, state)
{
  if (isnull(c))
  {
    state["result"] += "%";
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c == "(")
  {
    if (isnull(state["kw"]))
      exit(1, "vsprintf used a keyword lookup when no keywords were provided.");

    # Start a new keyword.
    state["keywords"][max_index(state["keywords"])] = "";

    state["format_pos"]++;
    state["state"] = _FORMAT_STATE_KEYWORD;
  }
  else if (c == "%")
  {
    state["result"] += "%";
    state["format_pos"]++;
    state = _printf_reset_state(state:state);
  }
  else if (c =~ "^[a-zA-Z]$")
  {
    state["state"] = _FORMAT_STATE_TYPE;
  }
  else if (c =~ "^[0-9]$")
  {
    state["state"] = _FORMAT_STATE_WIDTH;
  }
  else
  {
    state["state"] = _FORMAT_STATE_FLAGS;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where a '%(' has just been read and we're processing a keyword.
#
# If the string ends, go to the DONE state (technically invalid).
#
# If the character is a ')', go to PERCENT.
#
# Everything else, stay in this state.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_keyword(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c == ")")
  {
    state["state"] = _FORMAT_STATE_PERCENT;
    state["format_pos"]++;
  }
  else
  {
    # Append character to the last keyword.
    state["keywords"][max_index(state["keywords"]) - 1] += c;
    state["format_pos"]++;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where a percent sign has just been read and we're processing non-
# alphanumeric data (ie, flags).
#
# If the string ends, go to the DONE state (technically invalid).
#
# If the character is a digit, go to WIDTH.
#
# If the character is a period, go to PRECISION.
#
# If the character is a valid flag, set the appropriate value and continue
# reading flags.
#
# Everything else, go to TYPE.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_flags(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c == "+")
  {
    state["leading_plus"] = TRUE;
    state["format_pos"]++;
  }
  else if (c == " ")
  {
    state["leading_space"] = TRUE;
    state["format_pos"]++;
  }
  else if (c == "#")
  {
    state["alternate_form"] = TRUE;
    state["format_pos"]++;
  }
  else if (c == "-")
  {
    state["left_justify"] = TRUE;
    state["format_pos"]++;
  }
  else if (c == ".")
  {
    state["state"] = _FORMAT_STATE_PRECISION;
    state["format_pos"]++;
  }
  else if (c =~ "^[0-9]$")
  {
    state["state"] = _FORMAT_STATE_WIDTH;
  }
  else
  {
    state["state"] = _FORMAT_STATE_TYPE;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where we're reading the numerical field-width value.
#
# If the string ends, go to the DONE state (technically invalid).
#
# If the character is a digit, continue reading the WIDTH.
#
# If the character is a period, go to PRECISION.
#
# Everything else, go to TYPE.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_width(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c =~ "^[0-9]$")
  {
    # Handle format specifiers that start with 0
    if (state["width"] == 0 && c == "0")
      state["state"] = _FORMAT_STATE_PRECISION;
    else
      state["width"] = (state["width"] * 10) + int(c);
    state["format_pos"]++;
  }
  else if (c == ".")
  {
    state["state"] = _FORMAT_STATE_PRECISION;
    state["format_pos"]++;
  }
  else
  {
    state["state"] = _FORMAT_STATE_TYPE;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where we're reading the numerical precision value (comes after a
# period or zero, tells it how many zeroes or appropriately signed bytes to
# to add to the front of the format string).
#
# If the string ends, go to the DONE state (technically invalid).
#
# If the character is a digit, continue reading the PRECISION.
#
# Everything else, go to TYPE.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_precision(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else if (c =~ "^[0-9]$")
  {
    state["precision"] = (state["precision"] * 10) + int(c);
    state["format_pos"]++;
  }
  else
  {
    state["state"] = _FORMAT_STATE_TYPE;
  }

  return state;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where we're reading the one-character type.
#
# If the string ends, go to the DONE state (technically invalid).
#
# Anything else, read as a type and move to the READY state.
#
# @param state The current state table.
# @param c     The current character.
#
# @return The new state table.
##
function _handle_format_state_type(c, state)
{
  if (isnull(c))
  {
    state["state"] = _FORMAT_STATE_DONE;
  }
  else
  {
    state["type"] = c;
    state["state"] = _FORMAT_STATE_READY;
    state["format_pos"]++;
  }

  return state;
}

##
# Format a %b or %B string - binary.
#
# Returns the base-2 (binary) string formatted as specified by the various
# format specifiers.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_b(args, state)
{
  local_var current_arg, value, prepend;

  current_arg = _get_printf_arg(state:state, args:args);

  # If we're using the alternate form, prepend 0b to the string
  prepend = "";
  if (state["alternate_form"])
    prepend = "0b";

  value = ltostr(current_arg,
    base            : 2,
    twos_complement : !state["leading_plus"],
    width           : state["width"],
    precision       : state["precision"],
    leading_plus    : state["leading_plus"],
    leading_space   : state["leading_space"],
    left_justify    : state["left_justify"],
    prepend         : prepend
  );

  # If %B was given as the type, uppercase the string
  if (state["type"] == "B")
    value = toupper(value);

  return value;
}

##
# Format a %o string - octal.
#
# Returns the base-8 (octal) string formatted as specified by the various
# format specifiers.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_o(args, state)
{
  local_var current_arg, value, prepend;

  current_arg = _get_printf_arg(state:state, args:args);

  # If the alternate form is requested, prepend a '0' to the string
  prepend = "";
  if (state["alternate_form"])
    prepend = "0";

  value = ltostr(current_arg,
    base            : 8,
    twos_complement : !state["leading_plus"],
    width           : state["width"],
    precision       : state["precision"],
    leading_plus    : state["leading_plus"],
    leading_space   : state["leading_space"],
    left_justify    : state["left_justify"],
    prepend         : prepend
  );

  return value;
}

##
# Format a %d string - decimal. Also handles %i and %u, which are the same.
#
# Returns the base-10 (decimal) string formatted as specified by the various
# format specifiers.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_d(args, state)
{
  local_var precision;

  precision = state["precision"];

  return ltostr(_get_printf_arg(state:state, args:args),
    base          : 10,
    width         : state["width"],
    precision     : precision,
    leading_plus  : state["leading_plus"],
    leading_space : state["leading_space"],
    left_justify  : state["left_justify"]
  );
}

##
# Format a %x string - hex.
#
# Returns the base-16 (hex) string formatted as specified by the various
# format specifiers.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_x(args, state)
{
  local_var current_arg, precision, value, prepend;

  current_arg = _get_printf_arg(state:state, args:args);
  precision   = state["precision"];
  prepend     = "";
  if (state["alternate_form"])
    prepend = "0x";

  value = ltostr(current_arg,
    base            : 16,
    twos_complement : !state["leading_plus"],
    width           : state["width"],
    precision       : precision,
    leading_plus    : state["leading_plus"],
    leading_space   : state["leading_space"],
    left_justify    : state["left_justify"],
    prepend         : prepend
  );

  if (state["type"] == "X")
    value = toupper(value);

  return value;
}

##
# Format a %s string.
#
# Returns the string formatted as specified by the various format specifiers.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_s(args, state)
{
  local_var current_arg, value;

  current_arg = _get_printf_arg(state:state, args:args);

  value = string(current_arg);

  if (state["precision"])
    value = left(value, state["precision"]);
  if (state["left_justify"]) value = rpad(value, state["width"], char:" ");
  else value = lpad(value, state["width"], char:" ");

  return value;
}

##
# Format a %c character.
#
# Returns the integer converted into a character.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_c(args, state)
{
  local_var current_arg, value;

  current_arg = _get_printf_arg(state:state, args:args);

  value = raw_string(current_arg);
  if (state["left_justify"]) value = rpad(value, state["width"], char:" ");
  else value = lpad(value, state["width"], char:" ");

  return value;
}

##
# Format a %p character.
#
# Returns the object formatted as code.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_p(args, state)
{
  return obj_rep(_get_printf_arg(state:state, args:args));
}

##
# Format a %t character.
#
# Returns the list formatted as a table.
#
# @param state The current format string state.
# @param args  The array of arguments passed to sprintf.
#
# @return The formatted string.
##
function _format_t(args, state)
{
  local_var current_arg, i, len, max, num, value;

  current_arg = _get_printf_arg(state:state, args:args);

  # Find the longest of the names.
  max = 0;
  num = max_index(current_arg);
  for (i = 0; i + 1 < num; i += 2)
  {
    len = strlen(current_arg[i]);
    if (len > max)
      max = len;
  }

  # Format each name/value pair in a table.
  value = "";
  for (i = 0; i + 1 < num; i += 2)
  {
    value +=
      crap(data:" ", length:state["width"]) +
      rpad(current_arg[i], max, char:" ") +
      " : " +
      current_arg[i + 1] +
      '\n';
  }

  return value;
}

##
# Internal state-machine function for the printf suite of functions. Handles
# the state where we're finished reading the specifier, and all that's left is
# to build the string.
#
# This always returns to the READY state.
#
# @param state The current state table.
# @param c     The current character.
# @param args  The arguments array the user passed.
#
# @return The new state table.
##
function _handle_format_state_ready(args, c, state)
{
  if (tolower(state["type"]) == "b")
    state["result"] += _format_b(state:state, args:args);
  else if (state["type"] == "c")
    state["result"] += _format_c(state:state, args:args);
  else if (state["type"] =~ "[diu]")
    state["result"] += _format_d(state:state, args:args);
  else if (state["type"] == "o")
    state["result"] += _format_o(state:state, args:args);
  else if (tolower(state["type"]) == "p")
    state["result"] += _format_p(state:state, args:args);
  else if (state["type"] == "s")
    state["result"] += _format_s(state:state, args:args);
  else if (tolower(state["type"]) == "t")
    state["result"] += _format_t(state:state, args:args);
  else if (tolower(state["type"]) == "x")
    state["result"] += _format_x(state:state, args:args);
  else
    return NULL;

  # Consume an argument if a keyword was not used.
  if (max_index(state["keywords"]) <= 1)
    state["args_pos"]++;

  state = _printf_reset_state(state:state);

  return state;
}

##
# Internal state-machine function that resets the state to the default.
# Note that this doesn't reset every veriable, some state is maintained.
#
# @param state The current state.
#
# @return The state with the variables reset.
##
function _printf_reset_state(state)
{
  state["state"]          = _FORMAT_STATE_NEW;
  state["precision"]      = 0;
  state["width"]          = 0;
  state["pad_with_zero"]  = FALSE;
  state["leading_plus"]   = FALSE;
  state["leading_space"]  = FALSE;
  state["alternate_form"] = FALSE;
  state["left_justify"]   = FALSE;

  # Note that a path object is similar to a list, so we need to treat
  # it as such when adding it to another list.
  state["keywords"]       = make_list();
  state["keywords"][0]    = state["kw"];

  return state;
}

##
# Convert the args into a string, based on the format string.
#
# This conforms, for the most part, to ruby's Kernel.sprintf()
# function (with a few rare edgecases handled differently). The
# following is the format:
#
#   %[(keyword)...][flags][width][<.>precision][type]
#
# Note that Python's %(keyword) format is also supported, so you can
# have re-usable named arguments as well.
#
# The following flags are supported:
#
#   <space>  : Put a space at the start of all non-negative numbers.
#   #        : Use the alternate form. eg: %x becomes 0x<number>.
#   +        : Add a leading plus to non-negative numbers.
#   -        : Left-justify the result.
#   0 (zero) : Pad with zeroes, not spaces.
#
# The following flags are *NOT* supported:
#
#   <digit>$ : Use an absolute argument number.
#   *        : Use the next argument as the field width.
#
# The width represents the minimum amount of space the field can take
# up. If the string is shorter than the width, it's padded with spaces
# (unless a flag indicates otherwise) up to the proper size.
#
# The precision is the number of zeroes (or sign bytes in the case of
# twos' complement values) to pad the value with. In the case of
# string, this will truncate strings that are too short.
#
# And finally, the following types are supported:
#
#   %b and %B : Base 2 (binary)
#   %o        : Base 8 (octal)
#   %d        : Base 10 (decimal)
#   %i        : Same as %d
#   %u        : Same as %d
#   %x and %X : Base 16 (hex)
#   %s        : String
#   %c        : Character
#   %p        : Object representation via obj_rep()
#   %t        : Table-formatted list for reports
#
# The following types are *not* supported:
#
#   %e, %E, %f, %F, %g, %G, %a, %a : Floating point
#
# And finally:
#
#   %% : A double percent becomes a single percent
#
# @param format The format string.
# @param args   The list of arguments.
# @param kw     The list of keyword arguments.
#
# @return A string representing the format string with the args inserted.
##
function vsprintf(args, format, kw)
{
  local_var state, c, i;

  # Create the initial state.
  state = make_array();
  state["format_pos"] = 0;
  state["args_pos"] = 0;

  # Store the keywords using the path library, to guard against making
  # repeated copies of data in the event of a large data structure
  # being passed in.
  if (!isnull(kw))
    state["kw"] = path_store(kw);

  # Reset the state to where no format is in progress.
  state = _printf_reset_state(state:state);

  # If there was no format passed in, and args is not empty, assume
  # that the first element of args is the format. If there's no first
  # element, error out.
  if (isnull(format))
  {
    if (max_index(args) == 0)
      exit(1, "vsprintf was not implicitly nor explicitly given a format.");

    format = args[0];
    state["args_pos"] = 1;
  }

  while (state["state"] != _FORMAT_STATE_DONE)
  {
    c = NULL;
    if (state["format_pos"] < strlen(format))
      c = format[state["format_pos"]];

    if (state["state"] == _FORMAT_STATE_NEW)
      state = _handle_format_state_new(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_PERCENT)
      state = _handle_format_state_percent(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_KEYWORD)
      state = _handle_format_state_keyword(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_FLAGS)
      state = _handle_format_state_flags(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_WIDTH)
      state = _handle_format_state_width(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_PRECISION)
      state = _handle_format_state_precision(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_TYPE)
      state = _handle_format_state_type(state:state, c:c);
    else if (state["state"] == _FORMAT_STATE_READY)
      state = _handle_format_state_ready(state:state, c:c, args:args);
    else
      exit(1, "vsprintf ended up in an invalid state: " + state["state"] + ".");
  }

  # Free the keywords stored in the path library.
  if (!isnull(kw))
    path_free(state["kw"]);

  return state["result"];
}

##
# @see vsprintf(). This is the same thing, except the arguments are anonymous.
##
function sprintf(format, kw)
{
  return vsprintf(format:format, args:_FCT_ANON_ARGS, kw:kw);
}

##
# @see vsprintf(). This is the same thing, except it displays the result to the screen.
##
function vprintf(args, format, kw)
{
  display(vsprintf(format:format, args:args, kw:kw));
}

##
# @see vsprintf(). This is the same thing, except the arguments are anonymous
#      and the result is printed to the screen.
##
function printf(kw)
{
  vprintf(args:_FCT_ANON_ARGS, kw:kw);
}
