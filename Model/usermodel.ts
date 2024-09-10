import mongoose, { Document, Schema } from 'mongoose';

// Define the interface for the form document
interface IForm extends Document {
    name: string;
    phone: string;
    email: string;
    password: string;
    otp?: string;
    otpExpires?: Date;
    resetPasswordToken?: string;
    resetPasswordExpires?: Date;
    isVerified: boolean;
}

// Define the schema with appropriate types
const formSchema: Schema<IForm> = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    phone: {
        type: String,
        required: true,
        maxlength: 10,
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    otp: {
        type: String,
    },
    otpExpires: {
        type: Date,
    },
    resetPasswordToken: {
        type: String,
    },
    resetPasswordExpires: {
        type: Date,
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
});

// Create and export the model
const Form = mongoose.model<IForm>('Form', formSchema);
export default Form;
