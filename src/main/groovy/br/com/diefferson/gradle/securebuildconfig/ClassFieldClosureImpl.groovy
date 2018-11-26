/* The MIT License (MIT)
 *
 * Copyright (c) 2018 Santos Diefferson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package br.com.diefferson.gradle.securebuildconfig

import groovy.transform.EqualsAndHashCode

/**
 * @author Santos Diefferson
 */
@EqualsAndHashCode
final class ClassFieldClosureImpl implements ClassField {
   private static final long serialVersionUID = 1L

   final String type
   final String name
   final transient Closure<String> value
   final Set<String> annotations
   final String documentation

   ClassFieldClosureImpl (String type, String name, Closure<String> value) {
      this (type, name, value, Collections.<String>emptySet (), "")
   }

   ClassFieldClosureImpl (String type, String name, Closure<String> value,
                          Set<String> annotations, String documentation) {
      this.type = type
      this.name = name
      this.value = EncryptUtils.encrypt(name, value)
      this.annotations = Collections.unmodifiableSet (
         new LinkedHashSet<> (annotations))
      this.documentation = documentation
   }

   ClassFieldClosureImpl (ClassField classField) {
      this (classField.type, classField.name, classField.value,
         classField.annotations, classField.documentation)
   }

   String getValue () {
      return String.valueOf(EncryptUtils.decrypt(name,value.call()))
   }

   @SuppressWarnings('unused')
   private void writeObject(ObjectOutputStream s) throws IOException {
      s.defaultWriteObject()
   }

   @SuppressWarnings('unused')
   private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
      s.defaultReadObject()
   }
}
