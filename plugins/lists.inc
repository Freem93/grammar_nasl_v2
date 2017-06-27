###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# A suite of tools to better allow for a functional style of programming in NASL,
# together with functions for creating and manipulating lists and sets.
#
###

namespace collib {

_DEBUG_ = 0;
_TYPECHECKER_ = 0;

function dbgprint () { if (_DEBUG_) display(_FCT_ANON_ARGS[0]+'\n'); }

# First, we'll need to functionalize a few basic operators, since NASL
# doesn't have lambda expressions.

##
# @anonparam 1st the value to be returned
# @return 1st
# @remark id() is just the identity function, which we need in order
# to write certain higher-order functions in the simplest and clearest
# fashion.
##
function id()  { return _FCT_ANON_ARGS[0]; }

##
# @anonparam 1st any type that can be compared via '>'
# @anonparam 2nd any type comparable with 1st, via '>'
# @return boolean
# @remark gt() is a functional expression of the greater-than operator.
##
function gt()  { return _FCT_ANON_ARGS[0] > _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st any type that can be compared via '>='
# @anonparam 2nd any type comparable with 1st, via '>='
# @return boolean
# @remark ge() is a functional expression of the '>=' operator.
##
function ge()  { return _FCT_ANON_ARGS[0] >= _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st any type that can be compared via '<'
# @anonparam 2nd any type comparable with 1st, via '<'
# @return boolean
# @remark lt() is a functional expression of the lesser-than operator.
##
function lt()  { return _FCT_ANON_ARGS[0] < _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st any type that can be compared via '<='
# @anonparam 2nd any type comparable with 1st, via '<='
# @return boolean
# @remark lt() is a functional expression of the '<=' operator.
##
function le()  { return _FCT_ANON_ARGS[0] <= _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st any type that can be compared via '=='
# @anonparam 2nd any type comparable with 1st, via '=='
# @return boolean
# @remark eq() is a functional expression of the equality operator.
##
function eq()  { return _FCT_ANON_ARGS[0] == _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st boolean
# @anonparam 2nd boolean
# @return boolean TRUE if 1st or 2nd are TRUE, FALSE otherwise.
# @remark functional expression of the or (||) operator.
##
function or()  { return _FCT_ANON_ARGS[0] || _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st boolean
# @anonparam 2nd boolean
# @return boolean TRUE if 1st and 2nd are TRUE, FALSE otherwise.
# @remark functional expression of the and (&&) operator.
##
function and() { return _FCT_ANON_ARGS[0] && _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st integer
# @anonparam 2nd integer
# @return integer the sum of 1st and 2nd
# @remark functional expression of the '+' operator.
##
function plus() { return _FCT_ANON_ARGS[0] + _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st integer
# @anonparam 2nd integer
# @return integer the difference of 1st and 2nd
# @remark functional expression of the '-' operator.
##
function minus() { return _FCT_ANON_ARGS[0] - _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st integer
# @anonparam 2nd integer
# @return integer the product of 1st and 2nd
# @remark functional expression of the '*' operator.
##
function times() { return _FCT_ANON_ARGS[0] * _FCT_ANON_ARGS[1]; }

##
# @anonparam 1st the list of items to search the 1st list for
# @anonparam 2nd the list to search in
# @return boolean TRUE if all the items supplied are in the list,
# and FALSE otherwise.
# @remark See if all items in 'items' are in 'list'.
##
function is_sublist()
{
  local_var list = _FCT_ANON_ARGS[1];
  local_var items = _FCT_ANON_ARGS[0];

  local_var item;
  foreach (item in items)
  {
    if (!contains(list, item))
    {
      return FALSE;
    }
  }
  return TRUE;
}

##
# @anonparam 1st the list to search in
# @anonparam 2nd the list of items to search the 1st list for
# @return boolean TRUE if all the items supplied are in the list,
# and FALSE otherwise.
# @remark See if all items in 'items' are in 'list'.
##
function is_superlist()
{
  local_var list = _FCT_ANON_ARGS[0];
  local_var items = _FCT_ANON_ARGS[1];

  local_var item;
  foreach (item in items)
  {
    if (!contains(list, item))
    {
      return FALSE;
    }
  }
  return TRUE;
}


##
# @param f function pointer, an optional comparator function to use instead
# of '=='
# @param args list of arguments to pass to f along with its arguments from
# the list being searched.
# @anonparam 1st the list to be searched
# @anonparam 2nd the item to search for
# @return boolean, TRUE if the item (2nd) is contained in 1st, FALSE otherwise
##
function contains(f, args, list, item)
{
  local_var ap_args, i;
  if (isnull(list)) list = _FCT_ANON_ARGS[0];
  if (isnull(item)) item = _FCT_ANON_ARGS[1];
  if (isnull(args)) args = [];
  foreach (i in list)
  {
    if (isnull(f) && typeof(i) == typeof(item) &&
        equals(i,item))
    {
      return TRUE;
    }
    ap_args = list_copy(args);
    push(item, ap_args);
    if (!isnull(f) && apply(f:f, args:ap_args))  ##f(i, item))
    {
      return TRUE;
    }
  }
  return FALSE;
}

##
# @anonparam 1st list
# @anonparam 2nd list
# @param f a function pointer, to be used as the comparator in calling
# contains(). Optional.
# @return a list containing only those elements belonging to both
# 1st and 2nd. 
# @remark This function performs the set-theoretic intersection operation,
# and returns the result. It can be applied only to lists.
##
function intersection()
{
  local_var listA, listB;
  listA = _FCT_ANON_ARGS[0];
  listB = _FCT_ANON_ARGS[1];
  local_var intersection_list = make_list();
  local_var item;
  foreach (item in listA)
  {
    if (contains(listB, item, f:f))
    {
      push(item, intersection_list);
    }
  }
  return intersection_list;
}

##
# @anonparam 1st list
# @anonparam 2nd list
# @return a list containing only those elements belonging to both
# 1st and 2nd.
# @remark This function performs the set-theoretic union operation,
# and returns the result. It can be applied only to lists.
##
function union()
{
  local_var listA, listB;
  listA = _FCT_ANON_ARGS[0];
  listB = _FCT_ANON_ARGS[1];
  return make_list(listA, listB);
}

##
# @anonparam 1st list
# @anonparam 2nd list
# @param f a function pointer to a comparator to use in place of '==' when
# assessing membership in 2nd parameter, when 2nd parameter is a list
# @return a list containing only those elements belonging to 1st
# but not to 2nd. 
# @remark This function performs the set-theoretic union operation,
# and returns the result. It can be applied only to lists.
##
function subtract()
{
  local_var listA, listB;
  listA = _FCT_ANON_ARGS[0];
  listB = _FCT_ANON_ARGS[1];

  local_var diff = make_list();
  local_var item;
  foreach item (listA)
  {
    if (!contains(listB, item))
    {
      push(item, diff);
    }
  }
  return diff;
}

##
# @anonparam 1st list
# @anonparam 2nd list
# @return list containing only those elements that do not
# belong to the intersection of 1st and 2nd.
##
function difference ()
{
  return make_list(subtract(_FCT_ANON_ARGS[0], _FCT_ANON_ARGS[1]),
                   subtract(_FCT_ANON_ARGS[1], _FCT_ANON_ARGS[0]));
}

##
# @anonparam list
# @return a list of unique elements contained in the list, with
# repetitions removed.
# @remark This function runs in O(n^2) time. If the list
# is known to contain only hashable types, then it's better
# to remove duplicates like so:
#     s = new('set',list);
#     new_list = s.to_list();
##
function remove_duplicates()
{
  local_var new_list = [];
  foreach (item in _FCT_ANON_ARGS[0])
    if (!contains(new_list, item))
      push(item, new_list);
  return new_list;
}


##
# @param f a function pointer
# @anonparam list of arguments for f
# @return the result of calling f with the arguments supplied in list
# @remark Usage: apply(f:func, [1, 2, 3]); is the same as func(1, 2, 3)
# currently only set up to work for functions with 8 or fewer arguments,
##
function apply(f, args)
{
  if (isnull(args)) args = _FCT_ANON_ARGS[0];
  local_var num_args = max_index(args);

  if (num_args == 0) return f();
  else if (num_args == 1) return f(args[0]);
  else if (num_args == 2) return f(args[0], args[1]);
  else if (num_args == 3) return f(args[0], args[1], args[2]);
  else if (num_args == 4) return f(args[0], args[1], args[2], args[3]);
  else if (num_args == 5) return f(args[0], args[1], args[2], args[3], args[4]);
  else if (num_args == 6) return f(args[0], args[1], args[2], args[3], args[4], args[5]);
  else if (num_args == 7) return f(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
  else if (num_args == 8) return f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
  else exit(1, "apply() is not yet implemented for "+max_index(args)+" arguments.");
}


# The next two functions (range and enumerate) are so we can get rid of for(i=0;i<length(bla);i++) completely

##
# @anonparam integer lower bound, inclusive
# @anonparam integer upper bound, exclusive
# @return list of integers from lower bound to upper bound
# @remark Usage: foreach (number in range(0, 5))  # number takes on the values 0, 1, 2, 3, 4
##
function range()
{
  local_var start = _FCT_ANON_ARGS[0];
  local_var end = _FCT_ANON_ARGS[1];
  if (isnull(end))
  {
    end = start;
    start = 0;
  }
  local_var result = make_list();
  local_var i;
  for (i=start; i<end; i++)
  {
    push(i, result);
  }
  return result;
}

##
# @anonparam list of elements of type T
# @return list of arrays, of the form {'index': integer, 'val': T}
# @remark
# Usage:
# for (book in enumerate(books))
# {
#   display(book.index + ': ' + book.val);
# }
##
function enumerate()
{
  local_var list = _FCT_ANON_ARGS[0];
  local_var result = make_list();
  local_var i;
  for (i=0; i<max_index(list); i++)
  {
    push({'index':i, 'val':list[i]}, result);
  }
  return result;
}


##
# Return a list containing each item in list run through f.
#
# @anonparam The list to run on.
# @param f The function that each item will be run through.
# @param args Optional additional args to be passed to f
# *before* the last argument, taken from the list.
# @return The list [apply(f:\@f, args:args, x) | x in original list]
# @remark
# example: map(f:plus_one, [1,2,3])
#          -> [plus_one(1), plus_one(2), plus_one(3)]
#
# example: map(f:plus, [1,2,3], args:[4]);
#          -> [plus(4,1), plus(4,2), plus(4,3)]
# Note that the arguments are passed in a different order
# here than in the version of apply in the Compliance
# library, functional.inc. This is so as to better
# approximate the implementation of partial application and
# currying, found in most functional languages.
##
function map(f, args)
{
  if (isnull(args))
  {
    args = make_list();
  }
  local_var item;
  local_var new_list = make_list();
  foreach (item in _FCT_ANON_ARGS[0])
  {
    local_var ap_args = list_copy(args);
    push(item, ap_args);
    push(apply(f:f, args:ap_args), new_list);
  }
  return new_list;
}

##
# @anonparam list
# @return copy of that list, but not necessarily a copy 
# of its elements, which may be aliases
##
function list_copy ()
{
  local_var item, new_list = [];
  foreach (item in _FCT_ANON_ARGS[0])
    push(item, new_list);
  return new_list;
}

##
# @anonparam list
# @return recursive copy of a list, including its 
# elements, if they're also lists
##
function deep_copy ()
{
  local_var new_list = [];
  foreach (item in _FCT_ANON_ARGS[0])
  {
    if (typeof_ex(item) == 'list')
      item = deep_copy(item);
    push(item, new_list);
  }
  return new_list;
}


##
# @anonparam The list to run on.
# @param f The function that each item will be checked against.
# @param args Optional additional args to be added to the end of f.
# @return a list containing each item that returns a truthy value when passed through f.
# @remark
# example: filter(f:\@greater_than_3, [1, 2, 3, 4, 5])
#          -> [4, 5]
#
# example: filter(f:\@is_between, [1, 2, 3, 4, 5], args:[3, 5])
#          -> [4]
##
function filter(f, args)
{
  local_var list = _FCT_ANON_ARGS[0];
  local_var optional_following_arguments = args;

  if (isnull(optional_following_arguments))
  {
    optional_following_arguments = make_list();
  }

  local_var item;
  local_var new_list = make_list();
  foreach (item in list)
  {
    local_var ap_args = list_copy(args);
    push(item, ap_args);
    if (apply(f:f, args:ap_args))
      push(item, new_list);
  }
  return new_list;
}


##
# @anonparam The array to run on.
# @param f The function that each item will be checked against.
# @param args Optional additional args to be added to the end of f.
# @return an array containing each key/value pair that returns a truthy value
# when the value is passed through f.
# @remark
# example: filter_array(f:\@greater_than_3, {'a':1, 'b':3, 'c':4})
#          -> {'c':4}
#
# example: filter_array(f:\@is_between, {'a':1, 'b':3, 'c':4, 'd':5}, args:[3, 5])
#          -> {'c':4}
##
function filter_array(f, args)
{
  local_var array = _FCT_ANON_ARGS[0];
  local_var optional_following_arguments = args;

  if (isnull(optional_following_arguments))
  {
    optional_following_arguments = make_list();
  }

  local_var item;
  local_var new_array = {};
  local_var key;
  foreach (key in keys(array))
  {
    item = array[key];
    local_var ap_args = list_copy(args);
    push(item, ap_args);
    if (apply(f:f, args:ap_args))
      new_array[key] = item;
  }
  return new_array;
}


##
# @anonparam list
# @param f function pointer
# @param args arguments to pass to f along with each element from list
# @return pair p of lists with p[0] being the result of filtering the list
# through f with args, and p[1] being its complement.
# @remark Similar to filter(), except that it returns a pair (list)
# whose first element is a list containing elements of the list for
# which apply(f:f, args:make_list(args,x)) is truthy for x, and whose second
# element contains the remaining elements of the list.
##
function partition(f, args)
{
  local_var item;
  local_var list = _FCT_ANON_ARGS[0];

  local_var results = make_list();
  results[0] = make_list();
  results[1] = make_list();

  local_var index;
  foreach (item in list)
  {
    local_var bin, ap_args = list_copy(args);
    push(item, ap_args);
    if (apply(f:f, args:ap_args))
      bin = 0;
    else
      bin = 1;
    push(item, results[bin]);
  }
  return results;
}

##
# @param accessor, a function pointer to be called on each item
# before sorting. Optional.
# @param comparator, a dyadic boolean-returning function to be
# used instead of '<'. Optional.
# @anonparam list of elements to be sorted
# @return a sorted list of the elements in the list parameter
# @remark
# A mergesort implementation with an optional accessor function.
# The accessor is run on each item before they are sorted.
# comparator is an optional replacement for nasl's builtin '<',
# which is used to sort the values.
##
function merge_sort(accessor, comparator)
{
  local_var values = _FCT_ANON_ARGS[0];
  if (isnull(accessor)) { accessor = @id; }
  if (isnull(comparator)) { comparator = @lt; }

  if (max_index(values) <= 1)
  {
    return values;
  }

  local_var partitions = split_in_half(values);

  local_var left = merge_sort(partitions[0], accessor:accessor, comparator:comparator);
  local_var right = merge_sort(partitions[1], accessor:accessor, comparator:comparator);

  return merge_sort_merge(left, right, accessor:accessor, comparator:comparator);
}


function split_in_half()
{
  local_var list = _FCT_ANON_ARGS[0];
  local_var end = max_index(list) / 2;

  local_var results = make_list();
  results[0] = make_list();
  results[1] = make_list();

  local_var i;
  for (i = 0; i < end; i++)
  {
    results[0][max_index(results[0])] = list[i];
  }

  for (i = end; i < max_index(list); i++)
  {
    results[1][max_index(results[1])] = list[i];
  }

  return results;
}

function merge_sort_merge(accessor, comparator)
{
  local_var a = _FCT_ANON_ARGS[0];
  local_var b = _FCT_ANON_ARGS[1];
  if (isnull(accessor)) { accessor = @id; }
  if (isnull(comparator)) { comparator = @lt; }

  local_var index_a = 0;
  local_var index_b = 0;

  local_var result = make_list();
  local_var choose_a;

  while (index_a < max_index(a) || index_b < max_index(b))
  {
    if (index_a >= max_index(a))
      choose_a = FALSE;
    else if (index_b >= max_index(b))
      choose_a = TRUE;
    else if (comparator(accessor(b[index_b]), accessor(a[index_a])))
      choose_a = FALSE;
    else
      choose_a = TRUE;

    if (choose_a)
    {
      result[max_index(result)] = a[index_a];
      index_a++;
    }
    else
    {
      result[max_index(result)] = b[index_b];
      index_b++;
    }
  }
  return result;
}

##
# @param n   number of elements to take
# @anonparam list
# @return    list containing first n elements of list
##
function take (n)
{
  local_var list;
  list = _FCT_ANON_ARGS[0];
  if (isnull(n) || n == 0)
    return [];
  if (n >= max_index(list)) 
    return _FCT_ANON_ARGS[0];
  delete_element(endidx:max_index(list), idx:n, var:list); 
  return list;
}

##
# @param n   number of elements to take
# @anonparam list
# @return    list omitting first n elements of list
##
function drop (n)
{
  local_var list;
  list = _FCT_ANON_ARGS[0];
  if (n == 0)
    return list;
  if (n >= max_index(list))
    return [];
  delete_element(endidx:n-1, idx:0, var:list);
  return list;
}

##
# @param from the first index of the sublist
# @param to   last index of sublist [optional]
# @anonparam list from which to extract sublist
# @return a sublist of the list provided, from the 'from' index
# (inclusive) to the 'to' index (exclusive)
##
function sublist (from, to)
{
  local_var list, end;
  list = _FCT_ANON_ARGS[0];
  if (from < 0) from = 0;
  if (to < 0) to = 0;
  if (isnull(to)) to = max_index(list);
  if (isnull(from)) from = 0;
  if (from <= 0 && to >= max_index(list)) return list;
  if (to - from <= 0) return [];
  list = drop(list, n:from);
  end = (to - from);
  if (end < max_index(list))
    return take(list, n:end);
  else
    return list;
}

##
# @anonparam 1st: an element
# @anonparam 2nd: list to push to
# @return NULL
# @remark
# Pushes the first parameter onto the end the list,
# altering the list in-place.
#
# Usage: every instance of the form
# list = make_list(list, new_element);
# should be replaced with the more efficient
# push(new_element, list);
##
function push ()
{
  insert_element(idx:max_index(_FCT_ANON_ARGS[1]),
                 value:_FCT_ANON_ARGS[0],
                 var:_FCT_ANON_ARGS[1]);
  return;
}

##
# @anonparam list
# @return last element from list
# @remark
# Pops the last element off of a list, and returns that element.
# If the list is empty, pop() will throw an "Invalid index for
# array" error. Note that this function alters the list in-place.
##
function pop ()
{
  local_var x;
  if (equals([],_FCT_ANON_ARGS[0])) return NULL;
  x = _FCT_ANON_ARGS[0][max_index(_FCT_ANON_ARGS[0])-1];
  delete_element(endidx:max_index(_FCT_ANON_ARGS[0])-1,
                 idx:max_index(_FCT_ANON_ARGS[0])-1,
                 var:_FCT_ANON_ARGS[0]); 
  return x;
}

##
# @param list
# @return the reversed image of that list.
##
function reverse ()
{
  local_var r, i;
  r = make_list();
  for (i = max_index(_FCT_ANON_ARGS[0])-1; i >= 0; i --)
    push(_FCT_ANON_ARGS[0][i], r);
  return r;
}

##
# @anonparam list
# @param f: dyadic function pointer (comparator)
# @return the most f element in the list, where f is a
# two-parameter boolean-returning comparator function pointer 
# (like \@le, for example).
##
function most (f)
{
  local_var acc;
  acc = NULL;
  foreach elem (_FCT_ANON_ARGS[0])
  {
    if (isnull(acc) || f(elem, acc))
      acc = elem;
  }
  return acc;
}

##
# @anonparam list
# @param f function pointer (predicate)
# @param args additional arguments to pass to f
# @return TRUE if apply(f:f, args:args, x) == TRUE for all
# x in _FCT_ANON_ARGS[0], FALSE otherwise
##
function all (f, args)
{
  local_var m;
  m = map(f:f, args:args, _FCT_ANON_ARGS[0]);
  return reduce(f:@and, acc:TRUE, m);

}

##
# @param f function pointer (predicate)
# @param args additional arguments to pass to f
# @return TRUE if f(x) == TRUE for *some* x in _FCT_ANON_ARGS[0],
# and FALSE otherwise.
# @remark just an alias to contains
##
function any (f, args)
{
  return contains(f:f, args:args, _FCT_ANON_ARGS[0], TRUE);
}

##
# @anonparam list
# @return the maximum element of the list, under the > relation.
##
function max ()
{
  return most(f:@gt, _FCT_ANON_ARGS[0]);
}

##
# @anonparam list
# @return the minimum element of the list, under the < relation.
##
function min ()
{
  return most(f:@lt, _FCT_ANON_ARGS[0]);
}

##
# @anonparam a list of lists
# @return the length of the longest list in a list of lists.
##
function maxlength ()
{
  return max(map(f:@max_index, _FCT_ANON_ARGS[0]));
}

##
# @anonparam a list of lists
# @return the length of the shortest list in a list of lists
##
function minlength ()
{
  return min(map(f:@max_index, _FCT_ANON_ARGS[0]));
}

##
# @anonparam list of strings
# @return the length of the longest string in a list of strings.
##
function maxstrlen ()
{
  return max(map(f:@strlen, _FCT_ANON_ARGS));
}

##
# @anonparam a list of strings
# @return the length of the shortest string in a list of strings.
##
function minstrlen ()
{
  return min(map(f:@strlen, _FCT_ANON_ARGS));
}

##
# @anonparam list #1
# @anonparam list #2
# @return an array formed by pairing keys from list #1 with values
# from list #2.
##
function array_zip ()
{
  local_var num, i, m, arr;
  num = max_index(_FCT_ANON_ARGS);
  m = minlength(_FCT_ANON_ARGS); 
  arr = make_array();
  for (i = 0; i < m; i++)
  {
    arr[_FCT_ANON_ARGS[0][i]] = _FCT_ANON_ARGS[1][i];
  }
  return arr;
}

##
# @anonparam list #1
# @anonparam list #2
# @return a list of pairs, whose first elements are drawn from
# list #1, and whose second elements are drawn from list #2
##
function pair_zip ()
{
  local_var num, i, m;
  num = max_index(_FCT_ANON_ARGS);
  m = minlength(_FCT_ANON_ARGS); 
  plist = make_list();
  for (i = 0; i < m; i++)
  {
    push([_FCT_ANON_ARGS[0][i], _FCT_ANON_ARGS[1][i]], plist);
  }
  return plist;
}

##
# @anonparam list #1
# @anonparam list #2
# @param binary function pointer f
# @param args additional arguments to pass to f
# @return a list defined by {f(list1[i], list2[i]) | i under length of shortest list}
##
function zipwith (f, args)
{
  local_var num, i, m, lst;
  num = max_index(_FCT_ANON_ARGS);
  m = min(map(f:@max_index, _FCT_ANON_ARGS));
  lst = make_list();
  if (isnull(args)) args = [];
  for (i = 0; i < m; i++)
  {
    local_var val, ap_args = list_copy(args);
    push(_FCT_ANON_ARGS[0][i], ap_args);
    push(_FCT_ANON_ARGS[1][i], ap_args);
    val = apply(f:f, args:ap_args);
    push (val, lst);
  }
  return lst;
}

##
# @anonparam serializable data
# @remark A convenience function, mostly just for debugging this
# library. It serializes and prints data structures.
##
function show ()
{
  if (typeof_ex(_FCT_ANON_ARGS[0]) == 'set')
    return _FCT_ANON_ARGS[0].to_string();
  else
    return serialize(_FCT_ANON_ARGS[0]);
}

global_var __acc_table;
__acc_table = {'data':'', 'int':0, 'list':make_list()};
##
# @anonparam list
# @param f: function pointer to a binary function, whose return type
# is the same as its parameter types 
# @param acc: the accumulator value, should be same type as return type.
# @return the result of succesively applying f to the result of f(x, acc)
# for each element x of the list.
# @remark Example: reduce(f:\@plus, acc:0, [1,2,3]) evaluates as follows:
# {noformat}
# 0 + _     | [1,2,3]
# 0 + 1 = 1 | [2,3]
# 1 + 2 = 3 | [3]
# 2 + 3 = 5 | []
# {noformat}
##
function reduce (f, acc, args)
{
  local_var i, list;
  list = _FCT_ANON_ARGS[0];
  if (isnull(acc))
    acc = __acc_table[typeof_ex(_FCT_ANON_ARGS[0][0])];

  for (i = 0; i < max_index(list); i++)
  {
    local_var args_p = list_copy(args);
    push(acc, args_p);
    push(list[i], args_p);
    acc = apply(f:f, args:args_p);
  }
  return acc;
}
} # end namespace collib

