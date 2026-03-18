const mongoose=require('mongoose');

const connectDB=async()=>{
    try{
        const conn = await moongoose.connect(process.env.MONGO_URI, {
          // options (not always required in latest mongoose, but safe)
            useNewUrlParser: true,
            useUnifiedTopology: true
        });

        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch(error){
      console.error("Database connection error:", error.message);
      process.exit(1); // stop app if DB fails
    }
}