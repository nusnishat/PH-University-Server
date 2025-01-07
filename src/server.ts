import { Server } from 'http';
import mongoose from 'mongoose';
import app from './app';
import seedSuperAdmin from './app/DB';
import config from './app/config';

let server: Server;

async function main() {
  try {
    await mongoose.connect("mongodb+srv://mongoose:oRdevHrHQs7cLli7@cluster0.richl.mongodb.net/mongoose-first-project?retryWrites=true&w=majority&appName=Cluster0");

    seedSuperAdmin();
    server = app.listen(5000, () => {
      console.log(`app is listening on port 5000`);
    });
  } catch (err) {
    console.log(err);
  }
}

main();

process.on('unhandledRejection', (err) => {
  console.log(`😈 unahandledRejection is detected , shutting down ...`, err);
  if (server) {
    server.close(() => {
      process.exit(1);
    });
  }
  process.exit(1);
});

process.on('uncaughtException', () => {
  console.log(`😈 uncaughtException is detected , shutting down ...`);
  process.exit(1);
});
