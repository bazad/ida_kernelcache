#
# ida_kernelcache/kplist.py
# Brandon Azad
#
# Process kernel plists. This code is based on:
#   - https://github.com/python/cpython/blob/3.6/Lib/plistlib.py
#

import base64
from xml.etree.ElementTree import XMLTreeBuilder

class _KPlistBuilder(object):
    """A companion class for XMLTreeBuilder to parse a kernel-style property list."""
    # IMPLEMENTATION IDEA: The XMLTreeBuilder calls us at four points: when there's a new start
    # tag, when there's a new end tag, when there's data from a tag, and when there's no more data.
    # We build objects incrementally out of these notifications. Each tag type can implement
    # handlers for the start and end tags. Exactly one of these handlers must return an object that
    # represents the parsed plist entry. Collection entries must return the object from the start
    # tag handler, while leaf entries must return the object from the end tag handler. Once a
    # handler has produced an object for the plist entry, that object gets added to the result
    # using add_object. Collections are maintained in a collection stack. When a start tag handler
    # returns an object, that object is pushed onto the top of the collection stack to indicate
    # that it is the current collection. When an end tag handler does not return a value, that
    # indicates that the current collection is done and the collection stack is popped. When the ID
    # attribute is encountered, the subsequent call to add_object associates the object with that
    # ID. When a corresponding IDREF attribute is encountered, the start and end tag handlers are
    # skipped. Instead, once the next end tag is received, the previous object is looked up by ID
    # and passed to add_object.

    def __init__(self):
        self.collection_stack = []
        self.ids              = {}
        self.current_data     = []
        self.current_id       = None
        self.current_idref    = None
        self.current_key      = None
        self.root             = None
        self.start_handler    = {
                'dict':       self.start_dict,
                'array':      self.start_array,
        }
        self.end_handler      = {
                'dict':       self.end_dict,
                'key':        self.end_key,
                'true':       self.end_true,
                'false':      self.end_false,
                'integer':    self.end_integer,
                'string':     self.end_string,
                'data':       self.end_data,
        }
        self.attributes       = {
                'integer':    ('size',),
        }
        self.tags = set(self.start_handler.keys()).union(self.end_handler.keys())

    # XMLTreeBuilder calls.

    def start(self, tag, attr):
        intervening_data = self.get_data().strip()
        assert not intervening_data and not self.current_id
        # Check that the attributes are allowed.
        for attrname in set(attr.keys()).difference(('ID', 'IDREF')):
            if attrname not in self.attributes[tag]:
                raise ValueError('illegal attribute "{}" for tag "{}"'.format(attrname, tag))
        # Handle IDREF attribute.
        if self.current_idref is not None:
            raise ValueError('non-empty IDREF')
        self.current_idref = self.get_id_attr(attr, 'IDREF')
        if self.current_idref is not None:
            if self.current_idref not in self.ids:
                raise ValueError('tag has IDREF to non-existent ID')
            original_tag, _ = self.ids[self.current_idref]
            if tag != original_tag:
                raise ValueError('tag "{}" has IDREF to element with different tag "{}"'
                        .format(tag, original_tag))
            if len(attr) > 1:
                raise ValueError('tag has IDREF and another attribute')
            return
        # Handle ID attribute.
        self.current_id = self.get_id_attr(attr, 'ID')
        if self.current_id is not None and self.current_id in self.ids:
            raise ValueError('tag has previously used ID attribute')
        # Process the start tag if this is not an IDREF.
        handler = self.start_handler.get(tag, None)
        if handler:
            value = handler(attr)
            if value is not None:
                # This is a collection. Add the collection object then push a new context.
                self.add_object(tag, value)
                self.collection_stack.append(value)
        elif tag not in self.tags:
            raise ValueError('unrecognized tag "{}"'.format(tag))

    def end(self, tag):
        assert not (self.current_data and self.current_idref is not None)
        # If we have an ID reference, then directly add the referenced value.
        if self.current_idref is not None:
            _, value = self.ids[self.current_idref]
            self.current_idref = None
            self.add_object(tag, value)
            return
        # Otherwise, perform the end tag handler.
        handler = self.end_handler.get(tag, None)
        value = None
        if handler:
            value = handler()
        if value is not None:
            self.add_object(tag, value)
        else:
            # This is a collection. We just finished, so pop the context stack.
            self.collection_stack.pop()

    def data(self, data):
        if self.current_idref is not None:
            raise ValueError('non-empty IDREF')
        self.current_data.append(data)

    def close(self):
        assert not self.current_data and not self.collection_stack
        return self.root

    # Internal functions.

    def get_id_attr(self, attr, name):
        id_attr = attr.get(name, None)
        if id_attr is not None:
            try:
                return int(id_attr, 0)
            except ValueError:
                raise ValueError('invalid {} attribute'.format(name))
        return None

    def add_object(self, tag, value):
        if self.current_id is not None:
            assert self.current_id not in self.ids
            self.ids[self.current_id] = (tag, value)
            self.current_id = None
        if tag == 'key':
            # We are adding a key to a dictionary but don't yet have the value.
            if not self.collection_stack or type(self.collection_stack[-1]) != dict:
                raise ValueError('invalid key tag not in a dict')
            if self.current_key:
                raise ValueError('missing value for key in dict')
            self.current_key = value
        elif self.current_key is not None:
            # We are adding a key and value to a dictionary.
            assert type(self.collection_stack[-1]) == dict
            if self.current_key in self.collection_stack[-1]:
                raise ValueError('duplicate key "{}" in dict'.format(self.current_key))
            self.collection_stack[-1][self.current_key] = value
            self.current_key = None
        elif self.root is None:
            # We are setting the root object.
            self.root = value
        elif self.collection_stack and type(self.collection_stack[-1]) == list:
            # We are adding an object to an array (or other container).
            self.collection_stack[-1].append(value)
        else:
            # We have two values in a row not in a container.
            raise ValueError('unexpected element not in a container')

    def get_data(self):
        data = ''.join(self.current_data)
        self.current_data = []
        return data

    # Element tag handlers.

    def start_dict(self, attr):
        return {}

    def start_array(self, attr):
        return []

    def end_dict(self):
        if self.current_key is not None:
            raise ValueError('missing value for key in dict')

    def end_key(self):
        assert self.current_key is None
        return self.get_data()

    def end_true(self):
        if self.get_data():
            raise ValueError('true tag must be empty')
        return True

    def end_false(self):
        if self.get_data():
            raise ValueError('false tag must be empty')
        return False

    def end_integer(self):
        # TODO: The size attribute is currently ignored.
        return int(self.get_data(), 0)

    def end_string(self):
        return self.get_data()

    def end_data(self):
        return base64.b64decode(self.get_data())

def kplist_parse(plist):
    """Parse a kernel-style property list."""
    try:
        builder = _KPlistBuilder()
        parser  = XMLTreeBuilder(target=builder)
        parser.feed(plist)
        return parser.close()
    except:
        return None

