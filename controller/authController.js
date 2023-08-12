const { response, json } = require('express');
const bcryptjs = require('bcryptjs');

const Usuario = require('../models/usuario');
const { generarJWT } = require('../helpers/generate-jwt');
const { googleVerify } = require('../helpers/google-verify');

const login = async(req, res = response) => {
    const { email, password } = req.body;

    try {
        /* Verificar si el email existe */
        const usuario = await Usuario.findOne({ email });
        
        if( !usuario ) {
            return res.status(400).json({
                msg: '¡Usuario | Password no son correctos - Correo!'
            });
        }

        /* Si el usuario está activo */
        if( !usuario.status ) {
            return res.status(400).json({
                msg: '¡Usuario | Password no son correctos - Estado: false!'
            });
        }

        /* Verificar la contraseña */
        const validPassword = bcryptjs.compareSync( password, usuario.password );

        if( !validPassword ) {
            return res.status(400).json({
                msg: '¡Usuario | Password no son correctos - Password!'
            })
        }

        /* Generando el JWT */
        const token = await generarJWT( usuario.id );

        res.status(200).json({
            usuario,
            token
        });
    } catch (error) {
        console.log(error);

        return res.status(500).json({
            msg: 'Hable con el administrador'
        });
    }   
}

const googleSingIn = async(req, res = response) => {
    const { id_token } = req.body;

    try {
        const { email, name, picture } = await googleVerify( id_token );

        res.status(200).json({
            msg: 'Todo bien',
            email,
            name,
            picture
        })
    } catch (error) {
        res.status(400).json({
            ok: false,
            msg: 'El token no se pudo verificar.'
        })
    }
}

module.exports = {
    login,
    googleSingIn
}