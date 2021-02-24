/*
The MIT License (MIT)

Copyright (c) 2015 Markku-Juhani O. Saarinen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
if(typeof createSha3Module === 'undefined'){
    createSha3Module = Promise.reject(new Error('sha3 wasm module was not available'));
}

var sha3 = {
    
    internal: {
        module: null,
        bytesFromBuffer: function(internalBuffer,bufLen){
            const resultView = new Uint8Array(this.module.HEAP8.buffer, internalBuffer, bufLen);//view, not a copy
            const result = new Uint8Array(resultView);//copy, not a view!
            return result;
        },

        bufferFromBytes: function(bytes){
            var internalBuffer = this.create_buffer(bytes.length);
            this.applyBytesToBuffer(bytes, internalBuffer);
            return internalBuffer;
        },
        applyBytesToBuffer : function(bytes, internalBuffer){
            this.module.HEAP8.set(bytes, internalBuffer);
        },
        toHex: function(bytes){
            return Array.prototype.map.call(bytes, function (n) {
                return (n < 16 ? '0' : '') + n.toString(16)
              }).join('');
        },
        inputToBytes: function (input) {
            if (input instanceof Uint8Array) {
                return input;
            } else if (typeof (input) === 'string') {
                return (new TextEncoder()).encode(input);
            } else {
                throw new Error('Input must be an string, Buffer or Uint8Array')
            }
        }
    },
    
    /**
     * Checks if Sha3 support is ready (WASM Module loaded)
     * @return {Boolean}
     */
    isReady : function(){
        return this.internal.module!==null;
        
    },
    
    /**
     * Initializes a Hashing Context for Sha3
     * @param {Number} digest_size the number of bits for the digest size (512 or 256). 512 is default.
     * @return {Object} the context object for this hashing session. should only be used to hash one data source.
     */
    init: function(digest_size){
        
        if(typeof digest_size==="undefined"){
            digest_size = 512/8;
        }else{
            digest_size = (+digest_size)/8;
        }
        switch(digest_size){
            case 224/8:
            case 256/8:
            case 384/8:
            case 512/8:
                break;
            default:
                digest_size = 512/8;
        }
        return {
            digest_size : digest_size,
            context: this.internal.init(digest_size)
        };
    },
    
    /**
     * Update the hashing context with new input data
     * @param {Object} contextObject the context object for this hashing session
     * @param {Uint8Array} bytes an array of bytes to hash
     */
    update: function(contextObject, bytes){
        var inputBuffer = this.internal.bufferFromBytes(bytes);
        this.internal.update(contextObject.context, inputBuffer, bytes.length);
        this.internal.destroy_buffer(inputBuffer);
    },
    
    /**
     * Update the hashing context with new input data
     * @param {Object} contextObject the context object for this hashing session
     * @param {Object} value the value to use as bytes to update the hash calculation. Must be String or Uint8Array.
     */
    updateFromValue: function(contextObject, value){
        return this.update(contextObject, this.internal.inputToBytes(value));
    },
    
    /**
     * Finalizes the hashing session and produces digest ("hash") bytes.
     * Size of the returned array is always digest_size bytes long.
     * This method does not clean up the hashing context - be sure to call cleanup(ctx)!
     * @param {Object} contextObject the context object for this hashing session
     * @return {Uint8Array} an array of bytes representing the raw digest ("hash") value.
     */
    final: function(contextObject){
        var digestByteLen = contextObject.digest_size;
        var digestBuffer = this.internal.create_buffer(digestByteLen);
        //console.log("create buffer "+digestBuffer)
        //this.internal.final(contextObject.context,digestBuffer,digestByteLen);
        this.internal.final(digestBuffer,contextObject.context);
        
        var digestBytes = this.internal.bytesFromBuffer(digestBuffer, digestByteLen);
        //console.log("destroying buffer "+digestBuffer)
        this.internal.destroy_buffer(digestBuffer);
        return digestBytes;
    },
    
    /**
     * Cleans up and releases the Context object for the (now ended) hashing session.
     * @param {Object} contextObject the context object for this hashing session
     */
    cleanup: function(contextObject){
        this.internal.cleanup(contextObject.context);
    },
    
    /**
     * Calculates the Sha3 message digest ("hash") for the input bytes or string
     * @param {Object} input the input value to hash - either Uint8Array or String
     * @param {Number} digest_size the number of bits for the digest size (512 or 256). 512 is default.
     * @return {Uint8Array} an array of bytes representing the raw digest ("hash") value.
     */
    digest: function (input, digest_size) {
        input = this.internal.inputToBytes(input);
        var ctx = this.init(digest_size);
        this.update(ctx,input);
        var bytes = this.final(ctx);
        this.cleanup(input);
        return bytes;
    },
    
    /**
     * Calculates the Sha3 message digest ("hash") for the input bytes or string
     * @param {Object} input the input value to hash - either Uint8Array or String
     * @param {Number} digest_size the number of bits for the digest size (512 or 256). 512 is default.
     * @return {String} a hexadecimal representation of the digest ("hash") bytes.
     */
    digestHex: function (input, digest_size) {
        var bytes = this.digest(input,digest_size);
        return this.internal.toHex(bytes);
    }
};

createSha3Module().then(async module => {
    sha3.version= module.cwrap('version', 'number', []);
    sha3.internal.create_buffer= module.cwrap('create_buffer', 'number', ['number']);
    sha3.internal.destroy_buffer= module.cwrap('destroy_buffer', '', ['number']);
    sha3.internal.init= module.cwrap('sha3_init_stub', '', ['number']);
    sha3.internal.update= module.cwrap('sha3_update', 'number', ['number','number','number']);
    sha3.internal.final= module.cwrap('sha3_final', 'number', ['number','number']);
    sha3.internal.cleanup= module.cwrap('sha3_cleanup_stub', '', ['number']);
    sha3.internal.module = module;
});
